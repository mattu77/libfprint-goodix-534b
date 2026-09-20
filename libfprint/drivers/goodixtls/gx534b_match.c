// Small-area fingerprint matcher for the Goodix 534b: see gx534b_match.h
//
// Copyright (C) 2026 Mateusz Ryczko
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

#include "gx534b_match.h"

#include <math.h>
#include <string.h>

#define W GX534B_VIEW_W
#define H GX534B_VIEW_H
#define N 128                     /* POC FFT size (power of two >= W, H) */
#define NORM_RADIUS 8             /* local normalisation window: 17x17 */
#define BAND_FRAC 0.35            /* BLPOC keeps |k| <= 0.35 * (size/2) */
#define ROT_MAX 12
#define ROT_STEP 3
#define MIN_OVERLAP 0.4           /* common region must cover this much of a view */
#define MIN_REGION 24             /* ... and be at least this many px each way */
#define PEAK_SEARCH 6             /* BLPOC peak searched within +-6 px of alignment */

typedef struct { float re, im; } cpx;

/* ---- box filter (clipped window mean) ------------------------------------ */

static void
box_mean (const float *in, float *out, int h, int w, int r)
{
  g_autofree double *integ = g_malloc0 ((size_t) (h + 1) * (w + 1) * sizeof (double));

  for (int y = 0; y < h; y++)
    {
      double row = 0;
      for (int x = 0; x < w; x++)
        {
          row += in[y * w + x];
          integ[(y + 1) * (w + 1) + (x + 1)] = integ[y * (w + 1) + (x + 1)] + row;
        }
    }
  for (int y = 0; y < h; y++)
    {
      int y0 = MAX (0, y - r), y1 = MIN (h, y + r + 1);
      for (int x = 0; x < w; x++)
        {
          int x0 = MAX (0, x - r), x1 = MIN (w, x + r + 1);
          double s = integ[y1 * (w + 1) + x1] - integ[y0 * (w + 1) + x1] -
                     integ[y1 * (w + 1) + x0] + integ[y0 * (w + 1) + x0];
          out[y * w + x] = (float) (s / ((y1 - y0) * (x1 - x0)));
        }
    }
}

void
gx534b_prep_view (const guint16 *frame, const guint16 *baseline, float *view)
{
  g_autofree float *a = g_malloc (GX534B_VIEW_PIXELS * sizeof (float));
  g_autofree float *m = g_malloc (GX534B_VIEW_PIXELS * sizeof (float));

  /* drop sensor row 0 */
  for (int i = 0; i < GX534B_VIEW_PIXELS; i++)
    a[i] = (float) frame[i + GX534B_FRAME_W] - (float) baseline[i + GX534B_FRAME_W];

  box_mean (a, m, H, W, NORM_RADIUS);
  for (int i = 0; i < GX534B_VIEW_PIXELS; i++)
    a[i] -= m[i];
  for (int i = 0; i < GX534B_VIEW_PIXELS; i++)
    m[i] = a[i] * a[i];
  box_mean (m, view, H, W, NORM_RADIUS);
  for (int i = 0; i < GX534B_VIEW_PIXELS; i++)
    a[i] /= sqrtf (view[i] + 1e-6f);
  box_mean (a, view, H, W, 1);
}

void
gx534b_quantize (const float *view, gint8 *out)
{
  for (int i = 0; i < GX534B_VIEW_PIXELS; i++)
    out[i] = (gint8) CLAMP (lrintf (view[i] * 32.0f), -127, 127);
}

void
gx534b_dequantize (const gint8 *in, float *view)
{
  for (int i = 0; i < GX534B_VIEW_PIXELS; i++)
    view[i] = in[i] / 32.0f;
}

/* ---- rotation (bilinear, about the centre, zero outside) ------------------ */

static void
rotate_view (const float *in, float *out, float deg)
{
  float c = cosf (deg * (float) M_PI / 180.0f), s = sinf (deg * (float) M_PI / 180.0f);
  float cx = (W - 1) / 2.0f, cy = (H - 1) / 2.0f;

  for (int y = 0; y < H; y++)
    for (int x = 0; x < W; x++)
      {
        float dx = x - cx, dy = y - cy;
        float sx = c * dx + s * dy + cx, sy = -s * dx + c * dy + cy;
        int x0 = (int) floorf (sx), y0 = (int) floorf (sy);
        float fx = sx - x0, fy = sy - y0, v = 0;

        if (x0 >= 0 && y0 >= 0 && x0 + 1 < W && y0 + 1 < H)
          v = in[y0 * W + x0] * (1 - fx) * (1 - fy) + in[y0 * W + x0 + 1] * fx * (1 - fy) +
              in[(y0 + 1) * W + x0] * (1 - fx) * fy + in[(y0 + 1) * W + x0 + 1] * fx * fy;
        out[y * W + x] = v;
      }
}

/* ---- radix-2 FFT, N points --------------------------------------------- */

static void
fft_1d (cpx *d, int inverse)
{
  static float tw_re[N / 2], tw_im[N / 2];
  static gboolean tw_ready = FALSE;

  if (!tw_ready)
    {
      for (int i = 0; i < N / 2; i++)
        {
          tw_re[i] = cosf (-2.0f * (float) M_PI * i / N);
          tw_im[i] = sinf (-2.0f * (float) M_PI * i / N);
        }
      tw_ready = TRUE;
    }
  /* bit reversal */
  for (int i = 1, j = 0; i < N; i++)
    {
      int bit = N >> 1;
      for (; j & bit; bit >>= 1)
        j ^= bit;
      j ^= bit;
      if (i < j)
        {
          cpx t = d[i]; d[i] = d[j]; d[j] = t;
        }
    }
  for (int len = 2; len <= N; len <<= 1)
    {
      int step = N / len;
      for (int i = 0; i < N; i += len)
        for (int k = 0; k < len / 2; k++)
          {
            float wr = tw_re[k * step], wi = inverse ? -tw_im[k * step] : tw_im[k * step];
            cpx *a = &d[i + k], *b = &d[i + k + len / 2];
            float br = b->re * wr - b->im * wi, bi = b->re * wi + b->im * wr;
            b->re = a->re - br; b->im = a->im - bi;
            a->re += br; a->im += bi;
          }
    }
  if (inverse)
    for (int i = 0; i < N; i++)
      {
        d[i].re /= N; d[i].im /= N;
      }
}

static void
fft_2d (cpx *d, int inverse)
{
  cpx col[N];

  for (int y = 0; y < N; y++)
    fft_1d (d + y * N, inverse);
  for (int x = 0; x < N; x++)
    {
      for (int y = 0; y < N; y++)
        col[y] = d[y * N + x];
      fft_1d (col, inverse);
      for (int y = 0; y < N; y++)
        d[y * N + x] = col[y];
    }
}

static float
hann (int i, int n)
{
  return 0.5f - 0.5f * cosf (2.0f * (float) M_PI * i / (n - 1));
}

/* Hann-windowed, zero-padded spectrum of a view. */
static void
view_spectrum (const float *view, cpx *spec)
{
  memset (spec, 0, N * N * sizeof (cpx));
  for (int y = 0; y < H; y++)
    for (int x = 0; x < W; x++)
      spec[y * N + x].re = view[y * W + x] * hann (y, H) * hann (x, W);
  fft_2d (spec, 0);
}

/* Translation of b relative to a via phase-only correlation. */
static void
poc_shift (const cpx *fa, const cpx *fb, int *dy, int *dx)
{
  g_autofree cpx *r = g_malloc (N * N * sizeof (cpx));
  float best = -1e9f;
  int bi = 0;

  for (int i = 0; i < N * N; i++)
    {
      float re = fa[i].re * fb[i].re + fa[i].im * fb[i].im;
      float im = fa[i].im * fb[i].re - fa[i].re * fb[i].im;
      float mag = sqrtf (re * re + im * im) + 1e-9f;
      r[i].re = re / mag; r[i].im = im / mag;
    }
  fft_2d (r, 1);
  for (int i = 0; i < N * N; i++)
    if (r[i].re > best)
      {
        best = r[i].re; bi = i;
      }
  *dy = bi / N; *dx = bi % N;
  if (*dy > N / 2) *dy -= N;
  if (*dx > N / 2) *dx -= N;
}

/* ---- band-limited POC on the common region ------------------------------ */

/* DFT coefficients of a windowed rh x rw region for |k1| <= K1, |k2| <= K2
 * (separable: rows then columns). out is (2K1+1) x (2K2+1), k = -K..K. */
static void
band_dft (const float *img, int stride, int rh, int rw, int K1, int K2, cpx *out)
{
  int L2 = 2 * K2 + 1;
  g_autofree cpx *rows = g_malloc (rh * L2 * sizeof (cpx));
  g_autofree float *win = g_malloc (rh * rw * sizeof (float));
  g_autofree float *cw = g_malloc (rw * sizeof (float));
  g_autofree float *sw = g_malloc (rw * sizeof (float));
  g_autofree float *ch = g_malloc (rh * sizeof (float));
  g_autofree float *sh = g_malloc (rh * sizeof (float));

  for (int x = 0; x < rw; x++)
    {
      cw[x] = cosf (2.0f * (float) M_PI * x / rw); sw[x] = sinf (2.0f * (float) M_PI * x / rw);
    }
  for (int y = 0; y < rh; y++)
    {
      ch[y] = cosf (2.0f * (float) M_PI * y / rh); sh[y] = sinf (2.0f * (float) M_PI * y / rh);
    }
  for (int y = 0; y < rh; y++)
    {
      float wy = hann (y, rh);
      for (int x = 0; x < rw; x++)
        win[y * rw + x] = img[y * stride + x] * wy * hann (x, rw);
    }
  for (int y = 0; y < rh; y++)
    for (int k2 = -K2; k2 <= K2; k2++)
      {
        const float *row = win + y * rw;
        int step = (k2 % rw + rw) % rw, idx = 0;
        float re = 0, im = 0;
        for (int x = 0; x < rw; x++)
          {
            re += row[x] * cw[idx]; im -= row[x] * sw[idx];
            idx += step; if (idx >= rw) idx -= rw;
          }
        rows[y * L2 + (k2 + K2)].re = re; rows[y * L2 + (k2 + K2)].im = im;
      }
  for (int k1 = -K1; k1 <= K1; k1++)
    {
      int step = (k1 % rh + rh) % rh;
      for (int k2 = 0; k2 < L2; k2++)
        {
          float re = 0, im = 0;
          int idx = 0;
          for (int y = 0; y < rh; y++)
            {
              cpx t = rows[y * L2 + k2];
              re += t.re * ch[idx] + t.im * sh[idx];
              im += t.im * ch[idx] - t.re * sh[idx];
              idx += step; if (idx >= rh) idx -= rh;
            }
          out[(k1 + K1) * L2 + k2].re = re; out[(k1 + K1) * L2 + k2].im = im;
        }
    }
}

static float
blpoc_region (const float *a, const float *b, int stride, int rh, int rw)
{
  int K1 = MAX (2, (int) (rh / 2.0 * BAND_FRAC)), K2 = MAX (2, (int) (rw / 2.0 * BAND_FRAC));
  int L1 = 2 * K1 + 1, L2 = 2 * K2 + 1, NP = 2 * PEAK_SEARCH + 1;
  g_autofree cpx *fa = g_malloc (L1 * L2 * sizeof (cpx));
  g_autofree cpx *fb = g_malloc (L1 * L2 * sizeof (cpx));
  g_autofree cpx *e1 = g_malloc (NP * L1 * sizeof (cpx));   /* exp(+j 2pi k1 n1 / L1) */
  g_autofree cpx *e2 = g_malloc (NP * L2 * sizeof (cpx));
  g_autofree cpx *part = g_malloc (L1 * sizeof (cpx));
  float best = 0;

  band_dft (a, stride, rh, rw, K1, K2, fa);
  band_dft (b, stride, rh, rw, K1, K2, fb);
  for (int i = 0; i < L1 * L2; i++)
    {
      float re = fa[i].re * fb[i].re + fa[i].im * fb[i].im;
      float im = fa[i].im * fb[i].re - fa[i].re * fb[i].im;
      float mag = sqrtf (re * re + im * im) + 1e-9f;
      fa[i].re = re / mag; fa[i].im = im / mag;
    }
  for (int n = 0; n < NP; n++)
    {
      for (int k = 0; k < L1; k++)
        {
          float ph = 2.0f * (float) M_PI * (float) ((k - K1) * (n - PEAK_SEARCH)) / L1;
          e1[n * L1 + k].re = cosf (ph); e1[n * L1 + k].im = sinf (ph);
        }
      for (int k = 0; k < L2; k++)
        {
          float ph = 2.0f * (float) M_PI * (float) ((k - K2) * (n - PEAK_SEARCH)) / L2;
          e2[n * L2 + k].re = cosf (ph); e2[n * L2 + k].im = sinf (ph);
        }
    }
  /* inverse DFT of the band, evaluated around zero shift only (separable) */
  for (int n2 = 0; n2 < NP; n2++)
    {
      for (int k1 = 0; k1 < L1; k1++)
        {
          float re = 0, im = 0;
          for (int k2 = 0; k2 < L2; k2++)
            {
              cpx r = fa[k1 * L2 + k2], e = e2[n2 * L2 + k2];
              re += r.re * e.re - r.im * e.im; im += r.re * e.im + r.im * e.re;
            }
          part[k1].re = re; part[k1].im = im;
        }
      for (int n1 = 0; n1 < NP; n1++)
        {
          float re = 0, im = 0;
          for (int k1 = 0; k1 < L1; k1++)
            {
              cpx e = e1[n1 * L1 + k1];
              re += part[k1].re * e.re - part[k1].im * e.im; im += part[k1].re * e.im + part[k1].im * e.re;
            }
          float v = sqrtf (re * re + im * im) / (L1 * L2);
          if (v > best)
            best = v;
        }
    }
  return best;
}

/* ---- top level ---------------------------------------------------------- */

float
gx534b_match (const float *probe, const gint8 *views, int n_views)
{
  g_autofree cpx *fv = g_malloc (n_views * N * N * sizeof (cpx));
  g_autofree cpx *fp = g_malloc (N * N * sizeof (cpx));
  g_autofree float *view = g_malloc (GX534B_VIEW_PIXELS * sizeof (float));
  g_autofree float *rp = g_malloc (GX534B_VIEW_PIXELS * sizeof (float));
  g_autofree float *region_a = g_malloc (GX534B_VIEW_PIXELS * sizeof (float));
  g_autofree float *region_b = g_malloc (GX534B_VIEW_PIXELS * sizeof (float));
  float best = 0;

  for (int v = 0; v < n_views; v++)
    {
      gx534b_dequantize (views + v * GX534B_VIEW_PIXELS, view);
      view_spectrum (view, fv + v * N * N);
    }

  for (int deg = -ROT_MAX; deg <= ROT_MAX; deg += ROT_STEP)
    {
      rotate_view (probe, rp, (float) deg);
      view_spectrum (rp, fp);
      for (int v = 0; v < n_views; v++)
        {
          int dy, dx, y0, y1, x0, x1, rh, rw;

          /* shift of the rotated probe relative to the view */
          poc_shift (fv + v * N * N, fp, &dy, &dx);
          y0 = MAX (0, dy); y1 = MIN (H, H + dy);
          x0 = MAX (0, dx); x1 = MIN (W, W + dx);
          rh = y1 - y0; rw = x1 - x0;
          if (rh < MIN_REGION || rw < MIN_REGION || rh * rw < MIN_OVERLAP * H * W)
            continue;
          gx534b_dequantize (views + v * GX534B_VIEW_PIXELS, view);
          for (int y = 0; y < rh; y++)
            for (int x = 0; x < rw; x++)
              {
                region_a[y * rw + x] = view[(y0 + y) * W + (x0 + x)];
                region_b[y * rw + x] = rp[(y0 - dy + y) * W + (x0 - dx + x)];
              }
          float s = blpoc_region (region_a, region_b, rw, rh, rw);
          if (s > best)
            best = s;
        }
    }
  return best;
}
