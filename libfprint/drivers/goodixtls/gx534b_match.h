// Small-area fingerprint matcher for the Goodix 534b (108x87 px, ~5.4x4.4 mm)
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

/*
 * Minutiae matching does not work on a patch this small (2-9 real minutiae per
 * touch), so this uses phase correlation instead, following Ito et al.:
 *
 *   1. ridge map: frame - stored calibration frame, local mean/variance
 *      normalisation (window 17), light smoothing
 *   2. for each enrolled view and each rotation of the probe (+-12 deg, 3 deg
 *      steps): estimate the translation with phase-only correlation (POC) on
 *      Hann-windowed, zero-padded 128x128 images
 *   3. crop the common region of both images and compute the band-limited POC
 *      (BLPOC, lowest 35% of the spectrum) there; its peak height is the score
 *
 * Measured on this sensor: same finger with overlapping placement 0.60-0.87,
 * different finger <= 0.29, so views with no overlap look like impostors and
 * enrollment has to cover the finger with many overlapping views.
 */

#pragma once

#include <glib.h>

#define GX534B_VIEW_W 108
#define GX534B_VIEW_H 87                 /* sensor row 0 is always zero and dropped */
#define GX534B_VIEW_PIXELS (GX534B_VIEW_W * GX534B_VIEW_H)
#define GX534B_FRAME_W 108
#define GX534B_FRAME_H 88

#define GX534B_MATCH_THRESHOLD 0.45f     /* BLPOC peak: genuine >= ~0.6, impostor <= ~0.29 */

/* Build a ridge map view (GX534B_VIEW_PIXELS floats) from a raw decoded frame and
 * the stored calibration frame (both GX534B_FRAME_W*GX534B_FRAME_H, 12-bit). */
void  gx534b_prep_view (const guint16 *frame,
                        const guint16 *baseline,
                        float         *view);

/* Template storage: views are kept as int8, 1/32 units. */
void  gx534b_quantize (const float *view,
                       gint8       *out);
void  gx534b_dequantize (const gint8 *in,
                         float       *view);

/* Best BLPOC peak of @probe against @n_views int8 views (concatenated). */
float gx534b_match (const float *probe,
                    const gint8 *views,
                    int          n_views);
