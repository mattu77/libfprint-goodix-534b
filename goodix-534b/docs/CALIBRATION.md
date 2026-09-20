# Goodix 534b — DAC calibration algorithm (reverse-engineered)

The `d0` "not-ready" wall is the closed-loop **DAC calibration**. Fully reversed from
`wbdiMouse.dll` with Ghidra 12.1.3. Chip = Goodix **Milan-HV series** (GM168SEC).

## Architecture (who does what)
- `GoodixEngineAdapterMouse.dll` = image ALGORITHM layer (matching, quality). Talks to the
  UMDF driver via `DeviceIoControl(handle, 0x442140, inbuf[0]=0x46 ...)`. Post-capture it
  runs `EngineAdapterAcceptSampleData` (rejects: 5=too fast, 6=too slow, 7=bad/quality;
  checks `minImageQuality`).
- `wbdiMouse.dll` = USB/sensor protocol + DAC calibration. Builds the `0x20/0x32/0x34/0xAE`
  USB commands and the `d0` handling. **This is where calibration lives.**

## Call chain
1. `MilanHvSerDynamicAdjustDac` (milanhvsermcu.c) — orchestration. default `dac_h = 0x97`.
2. `HVDacDynamicAdjustUnify` / FUN_18003e330 (milanhvserunify.c, common/sgx) — takes TWO
   frames (base + after-a-DAC-change), copies them, calls the core.
3. `HVDefaultDacDynamicAdjust` (milanhvdacadj.c) — logs
   `press_mean / min_dac / hv_dac_data_h_otp / max_dac / cur_dac`; dispatches on
   `dac_adjust_type` (1 => TxPositiveDacDynamicAdjust).
4. `TxPositiveDacDynamicAdjust` (milanhvdacadj.c) — THE control loop (below).
5. `HuSetDac`/`SetRegDac` (milanh.c/milanj.c) — write the 4 DAC registers (reg `0x220`),
   adjusting from defaults (ctx+0x78) by a step. DAC value packed as `(v<<4)|8`.

## The control loop (TxPositiveDacDynamicAdjust)
Inputs: `base` frame (param_1), `after` frame (param_2), rows=param_3, cols=param_4,
`*param_5` = current DAC (9-bit, masked `& 0x1ff`).

1. **press_mean** = mean of INTERIOR pixels of the base frame (exclude the 1-pixel border),
   skipping "hot" pixels: value > `0xed8` (3800) OR large base-vs-after diff. `press_mean`
   is stored to `DAT_18022c0d4`.
2. **coverage** = (#non-zero interior px)/interior_area (`local_30`), and valid-px ratio
   (`local_28`); gated by thresholds `_DAT_180171c98`, `_DAT_180171c90` (doubles).
3. **adjust** (9-bit DAC, hysteresis: 3 consecutive same-direction readings via counters
   `DAT_18022c0f0/f4` before acting):
   - press_mean > `target_high` (DAT_18022c0aa)  → too bright → DAC += step (clamp max_dac DAT_18022c0be)
   - press_mean < `target_low`  (DAT_18022c0ac)  → too dark   → DAC -= step (clamp min_dac DAT_18022c0c0)
   - else fine-tune into inner band [`DAT_18022c0b0`, `DAT_18022c0ae`]
   - step = |press_mean - band_edge| / `fVar2` (float divisor DAT_18022c0cc), capped 300, min 1
4. Result written back to `*param_5` (`& 0x1ff`), i.e. the new DAC used in the next
   `0x32`/`0x34` capture command.

## CONCRETE CONSTANTS (retrieved 2026-09-19)

From `HVDacDynamicAdjustArgInit` (FUN_180075d38, milanhvdacadj.c) — **hardcoded** for
`dac_adjust_type == 1` (the TxPositive path):
- target_high = **3000**, target_low = **800**
- inner_high  = **2700** (0xa8c), inner_low = **1100** (0x44c)
- (mid 0x76c=1900); step-numerator-up DAT_18022c0bc = **800**, down DAT_18022c0ba = **300**

For `dac_adjust_type == 2`: target_high=1000, target_low=3300, inner_high=1300,
inner_low=3000, ...

From .rdata (static doubles):
- divisor multiplier A (DAT_180171c80) = **0.283**  (chip_type default)
- divisor multiplier B (DAT_180171c88) = **0.326**  (chip_type 0x1c..0x1d)
- coverage threshold hi (_DAT_180171c98) = **0.95**
- coverage threshold lo (_DAT_180171c90) = **0.40**
Other constants: default dac_h = **0x97**, hot-pixel threshold = **0xed8 (3800)**,
DAC width = **9-bit (0x1ff)**, FDT defaults Tcode=**0x80**, Diff=**0x15**.

## Derived config formulas (from OTP inputs)
    divisor  = mult * hv_tcode_data_otp        (mult = 0.283, or 0.326 for chip 0x1c-0x1d)
    min_dac  = hv_dac_data_h_otp - (300 / divisor) - 1     (clamp >= 0)
    max_dac  = hv_dac_data_h_otp + 1 + (800 / divisor)     (clamp <= 0x1ff)
    cur_dac starts at hv_dac_data_h_otp (== dac_data_h_dynamic)

## OTP decode (GetTcodeAndDiffFromOtp, chicagohs.c)
64-byte OTP buffer; calibration byte b = OTP[0x2a] (validated: OTP[0x2a]==~OTP[0x2b], or
OTP[0x2d]==~OTP[0x2b], or OTP[0x2a]==OTP[0x2d]). Then:
    tcode = ((b >> 4) + 1) * 0x10 + 0x40
    diff  = ((((b & 0xf) + 2) * 0x6400) / tcode & 0xffff) / 3) >> 4

## Error taxonomy (from FUN_180007700) — what a failing fetch means
    -0x200009 Read OTP data failed   -0x200003 Read from MCU failed
    -0x200002 MCU data format wrong  -0x200001 MCU data type wrong
    -0x200008 Reset Sensor failed    -0x200006 Wakeup MCU failed
    GTLS/AES: handshake/HMAC/decrypt errors (secure channel)

## STILL NEEDED: the raw OTP contents
The only remaining unknowns are the device's OTP bytes: hv_tcode_data_otp,
hv_dac_data_h_otp, chip_type, dac_adjust_type (and the OTP calibration byte at 0x2a).
These are read from the device OTP at init (NOT run by plain CaptureSample, so a memory
dump of the config globals stays zero). Options: (a) find/RE the OTP-read USB command and
read it from Linux; (b) trigger a Windows ENROLLMENT (which runs the DAC-adjust init) then
dump globals 0x22c090..0x22c0d4 from WUDFHost. NOTE: min/max_dac just bound a 9-bit search,
so a Linux implementation can converge empirically over [0,0x1ff] toward press_mean in
[1100,2700] without the exact OTP, using the step formula.

## (original) Config/OTP globals (runtime, wbdiMouse.dll @ 0x18022c0xx)
| name | global | meaning |
|---|---|---|
| target_high | DAT_18022c0aa | upper press_mean bound |
| target_low  | DAT_18022c0ac | lower press_mean bound |
| inner_high  | DAT_18022c0ae | fine-band upper |
| inner_low   | DAT_18022c0b0 | fine-band lower |
| divisor     | DAT_18022c0cc | step = delta/divisor (float) |
| min_dac     | DAT_18022c0c0 | DAC lower clamp |
| max_dac     | DAT_18022c0be | DAC upper clamp |
| default dac_h | 0x97 (const) | starting DAC high |
| hot-pixel thr | 0xed8 (const) | exclude px > 3800 |
| FDT defaults | Tcode=0x80, Diff=0x15 | finger-detect (istouchbyfinger.c FdtInit) |
| OTP read | GetTcodeAndDiffFromOtp | reads OTP Tcode/diff + hv_dac_data_h_otp |

## To finish a Linux capture
1. Read OTP calibration refs + the config constants above (need the OTP-read USB command;
   or dump the running driver's .data to get the concrete values once).
2. Loop: capture base+after frames (0x32/0x34 with current DAC), compute press_mean over
   interior non-hot pixels, adjust the 9-bit DAC per the rule, write it into the next
   0x32/0x34, repeat until press_mean is in [inner_low, inner_high].
3. Then `0x20(0005)` returns the image (no more d0); decrypt via our TLS session keys.

Ghidra project: scratchpad/ghproj (both DLLs analyzed). Scripts: DecompDAC.java,
DecompAddrs.java (GHIDRA_ADDRS env). Raw decomp: scratchpad/{dac_decomp,core_decomp,
adjust,formula}.txt.
