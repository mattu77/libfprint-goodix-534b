# Goodix 534b — complete capture flow (verified by dynamic trace)

Established 2026-09-19 by Frida-hooking the live Windows driver (WUDFHost) in the VM:
the logger (wbdiMouse FUN_1800c3ef0) for the call flow, and WINUSB.DLL!WinUsb_WritePipe
for the exact USB OUT bytes. SGX runs in sim mode here, so the enclave is in normal
hookable memory.

## The steady capture poll cycle (exact USB OUT, ep 0x01)
Repeats continuously while a WinBio capture/enroll session is open:
    0x20(0005)   a00e00ae 200b0005 ...        get image  (polled EVERY cycle)
    0x34         a03300d3 3430000e 01.. 80XX  switch FDT-up mode (DAC cal payload)
    0xAE         a00700a7 ae040001 0101f5     arm
    0x34         a03300d3 3430000e 01.. 80XX  FDT-up
    0x32         a03300d3 3230001c 01.. 80XX  switch FDT-down mode (DAC cal payload)

## KEY FACTS (why my Linux replay got perpetual d0)
1. **`d0` is NORMAL.** Windows sends `0x20` every cycle and gets `d0` ("not ready") until
   the device has actually captured a frame. `d0` was never an error — my replay's `d0`
   matched Windows' idle behavior.
2. **The `0x32`/`0x34` payloads carry DAC calibration values that CHANGE every cycle**
   (observed `0x32`: 80ac→80b1→80b3→80b4; `0x34`: 801780→809880→809d80→...). The driver
   runs the closed-loop DAC calibration (TxPositiveDacDynamicAdjust, see CALIBRATION.md)
   LIVE, adjusting these bytes from ADC feedback.
3. **Feedback source:** the `0x32`/`0x34` responses are FDT frames (subcmd..`1d`.. then
   12-bit ADC samples). The driver reads them, computes press_mean, and adjusts the 9-bit
   DAC toward the target band [1100,2700] (outer [800,3000]).
4. **Image delivery:** the device autonomously detects a finger-DOWN transition (McuParseFdt,
   "fdt touch flag" ~0xecc) once calibrated; it captures a frame internally; the next
   `0x20` returns it as a TLS application_data record (`0x37b9` on the wire, `0x37b0` raw
   after decrypt) which the driver decrypts (RecvTlsPackage/tls_read) and parses
   (SgxFpParseImage). My TLS-PSK session can decrypt this.
5. My replay sent FIXED DAC values (from an old capture), so the device never converged to
   a calibrated state → it never captured a frame → `0x20` returned `d0` forever, even with
   a finger present and correctly detected (ADC 0xff0f).

## What a working Linux capture requires (fully specified now)
1. Handshake (done) + session setup (done).
2. Run the poll cycle, but ADJUST the DAC bytes in `0x32`/`0x34` each iteration:
   - parse the `0x32`/`0x34` ADC response -> press_mean over interior pixels (exclude
     border + hot px >0xed8),
   - adjust the 9-bit DAC per TxPositiveDacDynamicAdjust (constants in CALIBRATION.md:
     target band 1100-2700, step=|delta|/divisor cap 300, clamp min/max_dac),
   - write the adjusted DAC back into the next `0x32`/`0x34` command,
3. With a finger present and the DAC converged, `0x20` returns the image; feed the TLS
   record to our ssl session and decrypt.

## Remaining unknowns for the implementation
- Exact byte offset(s) of the adjustable DAC value(s) inside the 55-byte `0x32`/`0x34`
  payloads (the `80XX` array) and how press_mean maps to them. The `0x34` payload varies a
  lot (whole array) vs `0x32` (one trailing byte) — needs a short empirical mapping pass.
- The divisor = 0.283 * hv_tcode_data_otp needs the OTP tcode (or can be treated as a tuning
  constant since the loop self-corrects).

## Tooling (all saved)
- Ghidra 12.1.3 project scratchpad/ghproj (3 DLLs analyzed).
- Frida hooks: hook.js (WinUsb_WritePipe/ReadPipe byte dumper + logger tracer), trace.py.
- windows-usb-writes.log (exact OUT byte sequence of a live capture).
- gxsession.py (Linux driver: handshake, setup, capture attempts).

## Working capture (2026-09-19) — see driver-linux/gxfinal.py

1. TLS-PSK handshake, then **0xD4** (TLS_SUCCESSFULLY_ESTABLISHED, body `00 00`). Without it
   0x20 answers `d0` forever.
2. 0xAE, switch_to_fdt_mode (0x36), fdt_up (0x34).
3. Poll fdt_down (0x32). Data frame `32 1d 00 02 00 | flags(2) | 12x LE u16 | ck` arrives
   only once a finger is detected; flags `ff 0f` = down, `ff 0b` = up.
4. get_img (0x20) with the Windows 10-byte body `05 00 .. 00` (the community `01 00` body
   returns an all-zero frame). Take two frames, keep the second (first is still settling).
5. Wait for flags `ff 0b` (finger up), then get_img again in fdt_down mode = **baseline**.
   Before the first touch of a session, and in fdt_up mode, get_img returns random bytes
   (std ~1180, zero frame-to-frame correlation) — the community nav0 calibration does not
   apply to this device.
6. Frame: 12-bit packed (6 bytes -> 4 px), 108x88, first row zero. fingerprint = finger -
   baseline (fixed-pattern noise is strongly row-striped; a plain high-pass shows the
   stripes, not ridges).

## libfprint driver (2026-09-20) — see libfprint-upstream/libfprint/drivers/goodixtls/goodix534b.c

Corrections to the recipe above, measured while writing the C driver:
- **0x32 does not block until finger-down.** It reports the finger state at command time
  (data frame only while a finger is present); the driver polls it every 300 ms.
- **The baseline is the stored calibration frame:** 0x20 with the 10-byte body and param
  0x01 (also 00/02/03) returns it, identical on every call, without a finger, stable across
  sessions. Param 0x05 returns the latest FDT capture. finger - calibration gives the
  cleanest images (see exp_p01.png); no post-lift capture is needed.
- Driver flow: activate (init commands, TLS + 0xD4, config, 0x36, 0x34, read calibration
  frame) -> poll 0x32 -> get_image x2 (keep 2nd) -> submit (finger - baseline, 2x upscale)
  -> poll until the finger is gone -> report finger off.
- fprintd integration works mechanically (enroll completes, verify runs). **Matching does
  not:** NBIS finds 2-9 real minutiae per 5.4x4.4 mm touch, bozorth3 needs >= 10 and scores
  0 even with the minimum lowered; plain ridge NCC gives no genuine/impostor separation
  (genuine 0.28-0.76, impostor 0.58-0.64). A small-area matcher would be a separate project.

## Matcher (2026-09-20) — libfprint-upstream/libfprint/drivers/goodixtls/gx534b_match.c

NBIS/bozorth3 and plain NCC cannot separate fingers on this patch size (see above), so the
driver is now a plain FpDevice with its own enroll/verify/identify and a host matcher:
band-limited phase-only correlation (Ito et al.). Ridge map = frame - calibration frame,
local mean/variance normalisation (17x17), light smoothing. For each enrolled view and
probe rotation (+-12 deg, 3 deg steps): POC on Hann-windowed 128x128 -> translation ->
common region (>= 40 %, >= 24 px) -> BLPOC (lowest 35 % of the spectrum) peak = score,
max over views. Threshold 0.45.

Measured: same finger with overlapping placement 0.60-0.88, different finger <= 0.29
(14 probes). Views without overlap score like impostors, so enrollment (16 touches) must
keep the finger roughly centred. Templates: FPI_PRINT_RAW "ay" = "GX534B01" | u16 n_views
| u16 pixels | int8 views (1/32 units). fprintd: enroll 16/16, verify-match 0.86,
other finger verify-no-match 0.21. ~180 ms per match against 8 views.
