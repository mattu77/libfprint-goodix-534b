// Goodix 534b (Dell MS819 mouse) TLS fingerprint driver for libfprint
//
// Copyright (C) 2026 Mateusz Ryczko
// Message layer based on the goodixtls 511 driver:
// Copyright (C) 2021 Alexander Meiler, Matthieu CHARETTE, Natasha England-Elbro
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

/*
 * Protocol summary (reverse engineered, see goodix-534b-re/FLOW.md):
 *
 *  open:  nop, firmware version, 3x preset-psk read, reset, read reg, read OTP,
 *         TLS-PSK handshake (we are the server) + 0xD4, upload MCU config, 0xC4,
 *         0xD2, query MCU state, switch_to_fdt_mode, fdt_up, then read the stored
 *         calibration frame (get_image param 01) = fixed pattern baseline.
 *  touch: poll fdt_down (0x32): it answers with a data frame only while a finger
 *         is present (flag bit 2) -> get_image (param 05) twice, keep the second
 *         (the first frame is still settling) -> ridge map = finger - baseline ->
 *         poll fdt_up/fdt_down until the finger is gone.
 *
 * Matching is done on the host with a phase-correlation matcher (gx534b_match.c):
 * the 5.4x4.4 mm patch has too few minutiae for libfprint's NBIS matcher, so this is
 * a plain FpDevice storing ridge-map views as raw print data rather than an image
 * device.
 */

#define FP_COMPONENT "goodixtls534b"

#include <glib.h>
#include <math.h>
#include <string.h>

#include "drivers_api.h"
#include "fpi-print.h"
#include "goodix.h"
#include "goodix_proto.h"
#include "goodix534b.h"
#include "gx534b_match.h"

#define IMAGE_TIMEOUT_MS 3000
#define FDT_POLL_TIMEOUT_MS 400    /* a present finger answers 0x32 within ~40 ms */
#define FDT_WAIT_TIMEOUT_MS 300    /* finger wait: re-poll 0x32 this often */
#define GARBAGE_STDDEV 900.0       /* no capture yet: ~1180, real frames: ~500-650 */
#define LIFT_CLEAR_POLLS 2
#define ENROLL_STAGES 16

#define TEMPLATE_MAGIC "GX534B01"

struct _FpiDeviceGoodixTls534b
{
  FpiDeviceGoodixTls parent;

  guint16 *baseline;    /* stored calibration frame (fixed pattern), per open */
  guint16 *finger;      /* decoded frame with the finger down */
  float   *probe;       /* ridge map of the last touch */
  int      lift_clear;  /* consecutive polls without a finger */

  GByteArray *enroll_views;   /* quantized views collected so far */
  int         enroll_stage;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls534b, fpi_device_goodixtls534b, FPI,
                      DEVICE_GOODIXTLS534B, FpiDeviceGoodixTls);

G_DEFINE_TYPE (FpiDeviceGoodixTls534b, fpi_device_goodixtls534b,
               FPI_TYPE_DEVICE_GOODIXTLS);

/* ---- helpers ------------------------------------------------------------ */

/* Send a raw command body; the callback gets the reply (reply=TRUE) or fires on
 * the ACK (reply=FALSE). */
static void
send_raw (FpDevice *dev, guint8 cmd, const guint8 *body, guint16 len,
          gboolean reply, guint timeout_ms, GoodixDefaultCallback cb, gpointer user_data)
{
  GoodixCallbackInfo *cb_info = g_malloc (sizeof (GoodixCallbackInfo));

  cb_info->callback = G_CALLBACK (cb);
  cb_info->user_data = user_data;
  goodix_send_protocol (dev, cmd, body, len, NULL, TRUE, timeout_ms, reply,
                        goodix_receive_default, cb_info);
}

static void
cb_strict (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }
  fpi_ssm_next_state (ssm);
}

/* fdt_up sometimes does not answer; a timeout there is not fatal. */
static void
cb_fdt_up (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  if (err)
    {
      if (!g_error_matches (err, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
        {
          fpi_ssm_mark_failed (ssm, err);
          return;
        }
      fp_dbg ("fdt_up timed out, continuing");
      g_error_free (err);
    }
  fpi_ssm_next_state (ssm);
}

/* Informational commands: log the reply, never fail on them. */
static void
cb_tolerant (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  if (err)
    {
      fp_warn ("optional command failed: %s", err->message);
      g_error_free (err);
    }
  else if (data && len)
    {
      g_autofree gchar *hex = data_to_str (data, MIN (len, 32));
      fp_dbg ("reply (%d bytes): %s", len, hex);
    }
  fpi_ssm_next_state (ssm);
}

/* 0x32/0x34 data frame payload: u16 type | u16 flags | 12 x u16 column readings.
 * The finger-event frames have flags ff0f (down) / ff0b (up). */
static gboolean
fdt_finger_down (const guint8 *data, guint16 len)
{
  return data && len >= 4 && (data[3] & 0x04);
}

/* 12-bit packed: 6 bytes -> 4 pixels. */
static guint16 *
decode_frame (const guint8 *raw, guint16 len)
{
  guint16 *px;
  int n = 0;

  if (len < GOODIX_534B_RAW_SIZE)
    {
      fp_warn ("short image: %d bytes", len);
      return NULL;
    }
  px = g_malloc (GOODIX_534B_PIXELS * sizeof (guint16));
  for (int i = 0; i + 6 <= GOODIX_534B_RAW_SIZE; i += 6)
    {
      const guint8 *c = raw + i;
      px[n++] = ((c[0] & 0xf) << 8) | c[1];
      px[n++] = (c[3] << 4) | (c[0] >> 4);
      px[n++] = ((c[5] & 0xf) << 8) | c[2];
      px[n++] = (c[4] << 4) | (c[5] >> 4);
    }
  return px;
}

static double
frame_stddev (const guint16 *px)
{
  double mean = 0, var = 0;

  for (int i = 0; i < GOODIX_534B_PIXELS; i++)
    mean += px[i];
  mean /= GOODIX_534B_PIXELS;
  for (int i = 0; i < GOODIX_534B_PIXELS; i++)
    var += (px[i] - mean) * (px[i] - mean);
  return sqrt (var / GOODIX_534B_PIXELS);
}

/* ---- templates: "GX534B01" | u16 n_views | u16 pixels | int8 views ------ */

static GVariant *
template_new (const GByteArray *views, int n_views)
{
  GByteArray *buf = g_byte_array_new ();
  guint16 hdr[2] = { GUINT16_TO_LE (n_views), GUINT16_TO_LE (GX534B_VIEW_PIXELS) };

  g_byte_array_append (buf, (const guint8 *) TEMPLATE_MAGIC, 8);
  g_byte_array_append (buf, (const guint8 *) hdr, sizeof (hdr));
  g_byte_array_append (buf, views->data, n_views * GX534B_VIEW_PIXELS);
  return g_variant_new_from_data (G_VARIANT_TYPE ("ay"), buf->data, buf->len, TRUE,
                                  (GDestroyNotify) g_byte_array_unref, buf);
}

/* Returns the views of @print (owned by the variant) or NULL if it is not ours. */
static const gint8 *
template_views (FpPrint *print, int *n_views, GVariant **keep)
{
  g_autoptr(GVariant) data = NULL;
  const guint8 *bytes;
  gsize len;
  guint16 hdr[2];

  if (fpi_print_get_type (print) != FPI_PRINT_RAW)
    return NULL;
  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE ("ay")))
    return NULL;
  bytes = g_variant_get_fixed_array (data, &len, 1);
  if (len < 12 || memcmp (bytes, TEMPLATE_MAGIC, 8) != 0)
    return NULL;
  memcpy (hdr, bytes + 8, sizeof (hdr));
  *n_views = GUINT16_FROM_LE (hdr[0]);
  if (GUINT16_FROM_LE (hdr[1]) != GX534B_VIEW_PIXELS ||
      len < 12 + (gsize) *n_views * GX534B_VIEW_PIXELS || *n_views == 0)
    return NULL;
  *keep = g_steal_pointer (&data);
  return (const gint8 *) bytes + 12;
}

/* ---- open: init commands, TLS, config, calibration frame ---------------- */

enum activate_states {
  ACTIVATE_NOP,
  ACTIVATE_FW_VERSION,
  ACTIVATE_PSK_READ_1,
  ACTIVATE_PSK_READ_2,
  ACTIVATE_PSK_READ_3,
  ACTIVATE_RESET,
  ACTIVATE_READ_REG,
  ACTIVATE_READ_OTP,
  ACTIVATE_NUM_STATES,
};

enum post_tls_states {
  POST_UPLOAD_CONFIG,
  POST_C4,
  POST_D2,
  POST_QUERY_MCU,
  POST_FDT_MODE,
  POST_FDT_UP,
  POST_BASELINE,
  POST_NUM_STATES,
};

static void
fw_version_cb (FpDevice *dev, gchar *firmware, gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }
  fp_dbg ("Device firmware: \"%s\"", firmware);
  fpi_ssm_next_state (ssm);
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_NOP:
      goodix_start_read_loop (dev);
      send_raw (dev, GOODIX_CMD_NOP, goodix_534b_nop, sizeof (goodix_534b_nop),
                FALSE, GOODIX_TIMEOUT, cb_tolerant, ssm);
      break;

    case ACTIVATE_FW_VERSION:
      goodix_send_query_firmware_version (dev, fw_version_cb, ssm);
      break;

    case ACTIVATE_PSK_READ_1:
      send_raw (dev, GOODIX_CMD_PRESET_PSK_READ, goodix_534b_psk_read_1,
                sizeof (goodix_534b_psk_read_1), TRUE, GOODIX_TIMEOUT, cb_tolerant, ssm);
      break;

    case ACTIVATE_PSK_READ_2:
      send_raw (dev, GOODIX_CMD_PRESET_PSK_READ, goodix_534b_psk_read_2,
                sizeof (goodix_534b_psk_read_2), TRUE, GOODIX_TIMEOUT, cb_tolerant, ssm);
      break;

    case ACTIVATE_PSK_READ_3:
      send_raw (dev, GOODIX_CMD_PRESET_PSK_READ, goodix_534b_psk_read_3,
                sizeof (goodix_534b_psk_read_3), TRUE, GOODIX_TIMEOUT, cb_tolerant, ssm);
      break;

    case ACTIVATE_RESET:
      send_raw (dev, GOODIX_CMD_RESET, goodix_534b_reset, sizeof (goodix_534b_reset),
                TRUE, 3000, cb_strict, ssm);
      break;

    case ACTIVATE_READ_REG:
      send_raw (dev, GOODIX_CMD_READ_SENSOR_REGISTER, goodix_534b_read_reg,
                sizeof (goodix_534b_read_reg), TRUE, GOODIX_TIMEOUT, cb_tolerant, ssm);
      break;

    case ACTIVATE_READ_OTP:
      send_raw (dev, GOODIX_CMD_READ_OTP, goodix_534b_read_otp,
                sizeof (goodix_534b_read_otp), TRUE, GOODIX_TIMEOUT, cb_tolerant, ssm);
      break;
    }
}

static void
on_baseline_image (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);
  guint16 *px = NULL;

  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }
  px = decode_frame (data, len);
  if (!px || frame_stddev (px) > GARBAGE_STDDEV)
    {
      g_free (px);
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "invalid calibration frame"));
      return;
    }
  fp_dbg ("calibration frame stddev %.0f", frame_stddev (px));
  g_free (self->baseline);
  self->baseline = px;
  fpi_ssm_next_state (ssm);
}

static void
post_tls_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case POST_UPLOAD_CONFIG:
      send_raw (dev, GOODIX_CMD_UPLOAD_CONFIG_MCU, goodix_534b_config,
                sizeof (goodix_534b_config), TRUE, 3000, cb_tolerant, ssm);
      break;

    case POST_C4:
      send_raw (dev, 0xc4, goodix_534b_c4, sizeof (goodix_534b_c4),
                FALSE, GOODIX_TIMEOUT, cb_tolerant, ssm);
      break;

    case POST_D2:
      send_raw (dev, 0xd2, goodix_534b_d2, sizeof (goodix_534b_d2),
                FALSE, GOODIX_TIMEOUT, cb_tolerant, ssm);
      break;

    case POST_QUERY_MCU:
      send_raw (dev, GOODIX_CMD_QUERY_MCU_STATE, goodix_534b_query_mcu,
                sizeof (goodix_534b_query_mcu), FALSE, GOODIX_TIMEOUT, cb_strict, ssm);
      break;

    case POST_FDT_MODE:
      send_raw (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_MODE, goodix_534b_fdt_mode,
                sizeof (goodix_534b_fdt_mode), TRUE, 3000, cb_strict, ssm);
      break;

    case POST_FDT_UP:
      send_raw (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP, goodix_534b_fdt_up,
                sizeof (goodix_534b_fdt_up), TRUE, 3000, cb_fdt_up, ssm);
      break;

    case POST_BASELINE:
      goodix_tls_read_image_payload (dev, goodix_534b_get_baseline,
                                     sizeof (goodix_534b_get_baseline),
                                     IMAGE_TIMEOUT_MS, on_baseline_image, ssm);
      break;
    }
}

static void
open_failed (FpDevice *dev, GError *error)
{
  GError *e2 = NULL;

  fp_err ("open failed: %s", error->message);
  goodix_dev_deinit (dev, &e2);
  g_clear_error (&e2);
  fpi_device_open_complete (dev, error);
}

static void
post_tls_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    {
      open_failed (dev, error);
      return;
    }
  fpi_device_open_complete (dev, NULL);
}

static void
tls_done (FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)
    {
      open_failed (dev, error);
      return;
    }
  fpi_ssm_start (fpi_ssm_new (dev, post_tls_run_state, POST_NUM_STATES),
                 post_tls_complete);
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    {
      open_failed (dev, error);
      return;
    }
  goodix_tls_init (dev, tls_done, NULL);
}

static void
dev_open (FpDevice *dev)
{
  GError *error = NULL;

  if (!goodix_dev_init (dev, &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }
  fpi_ssm_start (fpi_ssm_new (dev, activate_run_state, ACTIVATE_NUM_STATES),
                 activate_complete);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);
  GError *error = NULL;

  goodix_dev_deinit (dev, &error);
  g_clear_pointer (&self->baseline, g_free);
  g_clear_pointer (&self->finger, g_free);
  g_clear_pointer (&self->probe, g_free);
  fpi_device_close_complete (dev, error);
}

/* ---- one touch: wait, capture, ridge map, wait for lift ----------------- */

enum touch_states {
  TOUCH_FDT_DOWN,        /* poll until a finger is present */
  TOUCH_IMG_1,
  TOUCH_REARM_UP,
  TOUCH_FDT_DOWN_2,      /* second frame if the finger is still there */
  TOUCH_IMG_2,
  TOUCH_PROBE,
  TOUCH_LIFT_UP,         /* poll fdt_up + fdt_down until the finger is gone */
  TOUCH_LIFT_POLL,
  TOUCH_NUM_STATES,
};

static gboolean
check_cancelled (FpDevice *dev, FpiSsm *ssm)
{
  if (!fpi_device_action_is_cancelled (dev))
    return FALSE;
  fpi_ssm_mark_failed (ssm, g_error_new (G_IO_ERROR, G_IO_ERROR_CANCELLED, "cancelled"));
  return TRUE;
}

static void
on_fdt_down (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  if (err)
    {
      if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
        {
          g_error_free (err);
          if (!check_cancelled (dev, ssm))
            fpi_ssm_jump_to_state (ssm, TOUCH_FDT_DOWN);
          return;
        }
      fpi_ssm_mark_failed (ssm, err);
      return;
    }
  if (fdt_finger_down (data, len))
    {
      fp_dbg ("finger down");
      fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_PRESENT, FP_FINGER_STATUS_NEEDED);
      fpi_ssm_next_state (ssm);
    }
  else if (!check_cancelled (dev, ssm))
    {
      fpi_ssm_jump_to_state (ssm, TOUCH_FDT_DOWN);
    }
}

static void
on_fdt_down_2 (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  if (err)
    {
      if (!g_error_matches (err, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
        {
          fpi_ssm_mark_failed (ssm, err);
          return;
        }
      g_error_free (err);
      fpi_ssm_jump_to_state (ssm, TOUCH_PROBE);   /* keep the first frame */
      return;
    }
  if (fdt_finger_down (data, len))
    fpi_ssm_next_state (ssm);
  else
    fpi_ssm_jump_to_state (ssm, TOUCH_PROBE);
}

static void
on_finger_image (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);
  guint16 *px;

  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }
  px = decode_frame (data, len);
  if (!px)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "short image frame"));
      return;
    }
  fp_dbg ("finger frame stddev %.0f", frame_stddev (px));
  g_free (self->finger);
  self->finger = px;
  fpi_ssm_next_state (ssm);
}

static void
on_lift_poll (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);
  gboolean down = FALSE;

  if (err)
    {
      if (!g_error_matches (err, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
        {
          fpi_ssm_mark_failed (ssm, err);
          return;
        }
      g_error_free (err);   /* no data frame: no finger */
    }
  else
    {
      down = fdt_finger_down (data, len);
    }

  self->lift_clear = down ? 0 : self->lift_clear + 1;
  if (self->lift_clear >= LIFT_CLEAR_POLLS)
    {
      fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NONE, FP_FINGER_STATUS_PRESENT);
      fpi_ssm_next_state (ssm);
    }
  else if (!check_cancelled (dev, ssm))
    {
      fpi_ssm_jump_to_state (ssm, TOUCH_LIFT_UP);
    }
}

static void
touch_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case TOUCH_FDT_DOWN:
      send_raw (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN, goodix_534b_fdt_down,
                sizeof (goodix_534b_fdt_down), TRUE, FDT_WAIT_TIMEOUT_MS,
                on_fdt_down, ssm);
      break;

    case TOUCH_IMG_1:
    case TOUCH_IMG_2:
      goodix_tls_read_image_payload (dev, goodix_534b_get_image,
                                     sizeof (goodix_534b_get_image),
                                     IMAGE_TIMEOUT_MS, on_finger_image, ssm);
      break;

    case TOUCH_REARM_UP:
    case TOUCH_LIFT_UP:
      send_raw (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP, goodix_534b_fdt_up,
                sizeof (goodix_534b_fdt_up), TRUE, 1500, cb_fdt_up, ssm);
      break;

    case TOUCH_FDT_DOWN_2:
      send_raw (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN, goodix_534b_fdt_down,
                sizeof (goodix_534b_fdt_down), TRUE, FDT_POLL_TIMEOUT_MS,
                on_fdt_down_2, ssm);
      break;

    case TOUCH_PROBE:
      if (!self->probe)
        self->probe = g_malloc (GX534B_VIEW_PIXELS * sizeof (float));
      gx534b_prep_view (self->finger, self->baseline, self->probe);
      g_clear_pointer (&self->finger, g_free);
      self->lift_clear = 0;
      fpi_ssm_next_state (ssm);
      break;

    case TOUCH_LIFT_POLL:
      send_raw (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN, goodix_534b_fdt_down,
                sizeof (goodix_534b_fdt_down), TRUE, FDT_POLL_TIMEOUT_MS,
                on_lift_poll, ssm);
      break;
    }
}

static void touch_complete (FpiSsm *ssm, FpDevice *dev, GError *error);

static void
touch_start (FpDevice *dev)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);

  self->lift_clear = 0;
  g_clear_pointer (&self->finger, g_free);
  fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NEEDED, FP_FINGER_STATUS_NONE);
  fpi_ssm_start (fpi_ssm_new (dev, touch_run_state, TOUCH_NUM_STATES), touch_complete);
}

/* ---- actions ------------------------------------------------------------ */

static void
enroll_touch_done (FpDevice *dev)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);
  gint8 q[GX534B_VIEW_PIXELS];
  FpPrint *print = NULL;

  gx534b_quantize (self->probe, q);
  g_byte_array_append (self->enroll_views, (const guint8 *) q, sizeof (q));
  self->enroll_stage++;
  fp_dbg ("enroll: view %d/%d", self->enroll_stage, ENROLL_STAGES);
  fpi_device_enroll_progress (dev, self->enroll_stage, NULL, NULL);

  if (self->enroll_stage < ENROLL_STAGES)
    {
      touch_start (dev);
      return;
    }

  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, FALSE);
  g_object_set (print, "fpi-data", template_new (self->enroll_views, self->enroll_stage), NULL);
  g_clear_pointer (&self->enroll_views, g_byte_array_unref);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
verify_touch_done (FpDevice *dev)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);
  g_autoptr(GVariant) keep = NULL;
  FpPrint *print = NULL;
  const gint8 *views;
  int n_views = 0;
  float score;

  fpi_device_get_verify_data (dev, &print);
  views = template_views (print, &n_views, &keep);
  if (!views)
    {
      fpi_device_verify_complete (dev, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                                 "print is not a goodixtls534b template"));
      return;
    }
  score = gx534b_match (self->probe, views, n_views);
  fp_dbg ("verify: score %.2f over %d views (threshold %.2f)", score, n_views, GX534B_MATCH_THRESHOLD);
  fpi_device_verify_report (dev, score >= GX534B_MATCH_THRESHOLD ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                            NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

static void
identify_touch_done (FpDevice *dev)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);
  GPtrArray *prints = NULL;
  FpPrint *best = NULL;
  float best_score = 0;

  fpi_device_get_identify_data (dev, &prints);
  for (guint i = 0; prints && i < prints->len; i++)
    {
      g_autoptr(GVariant) keep = NULL;
      FpPrint *print = g_ptr_array_index (prints, i);
      int n_views = 0;
      const gint8 *views = template_views (print, &n_views, &keep);
      float score;

      if (!views)
        continue;
      score = gx534b_match (self->probe, views, n_views);
      fp_dbg ("identify: print %u score %.2f over %d views", i, score, n_views);
      if (score > best_score)
        {
          best_score = score;
          best = print;
        }
    }
  fpi_device_identify_report (dev, best_score >= GX534B_MATCH_THRESHOLD ? best : NULL, NULL, NULL);
  fpi_device_identify_complete (dev, NULL);
}

static void
touch_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);

  if (error)
    {
      fp_dbg ("touch failed: %s", error->message);
      g_clear_pointer (&self->enroll_views, g_byte_array_unref);
      fpi_device_action_error (dev, error);
      return;
    }
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  if (action == FPI_DEVICE_ACTION_ENROLL)
    enroll_touch_done (dev);
  else if (action == FPI_DEVICE_ACTION_VERIFY)
    verify_touch_done (dev);
  else if (action == FPI_DEVICE_ACTION_IDENTIFY)
    identify_touch_done (dev);
  else
    fpi_device_action_error (dev, fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceGoodixTls534b *self = FPI_DEVICE_GOODIXTLS534B (dev);

  g_clear_pointer (&self->enroll_views, g_byte_array_unref);
  self->enroll_views = g_byte_array_new ();
  self->enroll_stage = 0;
  touch_start (dev);
}

static void
dev_verify (FpDevice *dev)
{
  touch_start (dev);
}

static void
dev_identify (FpDevice *dev)
{
  touch_start (dev);
}

/* ---- class -------------------------------------------------------------- */

static void
fpi_device_goodixtls534b_init (FpiDeviceGoodixTls534b *self)
{
}

static void
fpi_device_goodixtls534b_class_init (FpiDeviceGoodixTls534bClass *class)
{
  FpiDeviceGoodixTlsClass *gx_class = FPI_DEVICE_GOODIXTLS_CLASS (class);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (class);

  gx_class->interface = GOODIX_534B_INTERFACE;
  gx_class->ep_in = GOODIX_534B_EP_IN;
  gx_class->ep_out = GOODIX_534B_EP_OUT;
  gx_class->psk = goodix_534b_psk;
  gx_class->psk_len = sizeof (goodix_534b_psk);

  dev_class->id = "goodixtls534b";
  dev_class->full_name = "Goodix TLS Fingerprint Sensor 534b (Dell MS819)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = ENROLL_STAGES;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* a tiny capacitive sensor in a mouse does not overheat */
  dev_class->temp_hot_seconds = -1;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->identify = dev_identify;

  fpi_device_class_auto_initialize_features (dev_class);
}
