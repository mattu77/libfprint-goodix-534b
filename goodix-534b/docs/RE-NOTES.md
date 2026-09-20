# goodix-534b Linux driver (Dell MS819 fingerprint mouse) — option 2 build

Status 2026-09-18: **secure channel WORKS on Linux.** `gxbridge.py` brings up the
sensor's TLS-PSK channel end-to-end with pure Python stdlib `ssl` + pyusb — no SGX,
no Windows, no external crypto libs. Handshake reaches `connected`
(`PSK-AES128-CBC-SHA256`, TLS 1.2), which cryptographically verifies the recovered PSK.

## Architecture (bottom-up)
1. **USB transport** — bulk EP 0x01 OUT / 0x83 IN, 64-byte packets.  [DONE: gx_proto.py]
2. **Command framing** — `A0|len16|hdrsum|subcmd|ilen16|body|cksum`,
   cksum=(0xAA-sum)&0xFF.  Responses may use magic 0xB0.  [DONE]
   - init 0x00, GET_VERSION 0xA8, finger-detect 0x32 (cleartext ADC),
     object-store 0xE4, fw-upload 0xF0, secure-session trigger **0xD0**.
3. **Secure-session trigger** — replay the 12-command sequence (init, version,
   object reads, 0xA2/0x82/0xA6 config, 0xD0) → sensor emits ClientHello.  [DONE: trigger.pkl]
4. **TLS-PSK tunnel** — raw TLS records wrapped `B0|len16|hdrsum|<rawTLS>` both
   directions.  Sensor is the TLS *client*; driver is the *server* holding the PSK.
   [DONE: gxbridge.py — Python ssl PSK server over MemoryBIO]
5. **In-TLS application protocol** — [IN PROGRESS ~80%: gxsession.py]. Drives from
   Linux: handshake -> setup replay -> capture loop (0x60 begin, 0xAE arm, 0x32
   frame, 0x20(0005) fetch). WORKING: full command framing (plaintext A0; image is
   a B2-wrapped TLS app-data 17 03 03 record), and FINGER DETECTION — the 0x32 ADC
   frame responds to a real touch, values (0x00ff0f..) matching the Windows scan.
   BLOCKER: the image fetch 0x20(0005) returns status d0 03 00 00 (not-ready) every
   cycle; the working Windows scan NEVER returns d0. Image decrypt (via our TLS keys)
   is ready and tested against the framing.

   PATH 1 (full capture) RESULT: captured a complete fresh session
   (fresh_out.pkl): 00 a8 a8 e4x3 a8 a8 a2 82 a6 d0 -> TLS handshake ->
   90 c4 c4 d2 36 20 36 70 82 20 36 -> 60 ae. This MATCHES our replay; 0x90 is
   byte-identical across two independent sessions (NOT session-bound). Only 0x36
   (per-session DAC calibration) and one 0x82 variant differ. So there is NO missing
   command and no session-bound config we get wrong -- the sequence is not the gap.

   PATH 2 (DLL RE) RESULT: capture pipeline is a chain-of-responsibility
   (CalibrateParameterRetestChain, SNRChain, PixelOpenShortChain,
   WBDICaptureDataReceiverChain, FlatEndChain...). Image = 16 bits/pixel, 1 channel;
   fetched via ImageFDTdownHandle (finger-detect-down). Production protocol code is
   engine_adapter\{engineadapter,messengerhandler}.cpp. The d0 is returned by the
   MCU FIRMWARE (f0_upload.bin), not the DLL -- the DLL only reacts to it. So the
   real decision ("deliver image vs d0") lives in the MCU firmware's engine state,
   gated by the DAC-calibration retest loop the driver runs before a good frame.

   OPTION 2 (full enrollment capture) RESULT: captured the working Windows poll
   (windows-enroll-poll.pcapng, 476 OUT frames). Cycle = ae -> 34 -> 32 -> 20(0005).
   We were MISSING 0x34 (a reference/reset frame before 0x32; full bytes now in
   capcmds.pkl). Adding it (with drain-synced xfer() to avoid the strict req-resp
   desync that HANGS the device -- recover via dev.reset()) still returns d0.

   ROOT CAUSE (final): the CLOSED-LOOP DAC CALIBRATION (CalibrateParameterRetestChain).
   The Windows driver iteratively adjusts the DAC values (the 0x80xx array in
   0x32/0x34) while reading test frames until quality passes; only THEN does the MCU
   deliver an image on 0x20. Our replay sends FIXED calibration from a prior session,
   so the frame is never accepted -> perpetual d0. Even Windows in the VM currently
   doesn't complete a capture (LocateSensor blocks), consistent with an uncalibrated
   device state after many reset cycles.

   TO FINISH: implement the closed-loop DAC calibration (reverse
   CalibrateParameterRetestChain in GoodixEngineAdapterMouse.dll: how it computes new
   DAC values from ADC readings + the quality criterion). Multi-day RE. A physical
   power-cycle of the mouse (clean baseline) may help before testing. The secure
   channel + control protocol + 0x34/0x32/0x20 sequence + finger-detect + image
   decrypt are all done and working from Linux TODAY.
6. **Provisioning / pairing** (option-2 core: mint our own PSK on any unit).  [TODO —
   needs a from-scratch pairing capture; the current PSK is unit-specific]
7. **libfprint driver** integration.  [TODO]

## Implementation attempt (2026-09-19) — result
Built the full capture (gxsession.py / gxcal.py / gxtap.py): handshake, setup, the exact
Windows cycle (0x20->0x34->0xAE->0x34->0x32), DAC-byte mapping (12 per-column 0x80XX at
offsets 18..40, cksum@54), FDT-response parsing (12 LE-u16 readings from byte 7),
finger-down detection, baseline + tap-transition handling, and fast polling to match the
Windows cadence. Across ~10 variants (fixed DAC, calibration loop, tap transitions, fast
poll) with the finger correctly detected (ADC 0xff0f), **0x20 always returns d0** on Linux,
while the SAME commands make Windows capture (dynamic trace confirmed Windows captures now:
SgxFpParseImage, RecvTlsPackage 0x37f0). Also confirmed: changing the payload DAC barely
moves the ADC readings (device already calibrated), so calibration is NOT the blocker.

## Conclusion: image plane gated by enclave secure-session authorization
Every command-layer variable is matched to Windows, yet 0x20 -> d0. The remaining
difference is the SECURE SESSION: Windows' SGX enclave does a post-handshake authorization
(GTLS PMK-HMAC: "get hmac of pmk from mcu" / "verify hmac of local and mcu") that binds
image delivery. My plain TLS-PSK session completes the handshake but the device still
answers 0xd0 (a secure-session response code) to image fetches. This step is:
 - not statically reversible: the enclave code has no cross-refs (SGX/ECALL-dispatched),
 - not dynamically capturable: it runs at device init, and WUDFHost restarts on device
   re-arrival, so Frida can't attach before the init runs (and the process to hook doesn't
   exist yet).
So the control plane (handshake, finger-detect, all commands) is fully open from Linux, but
the encrypted image plane is gated by an SGX-enclave secure-session authorization that
resists static RE, dynamic capture, and command-level replication. That is the definitive
wall for this hardware in this environment.

## What's proven
- The recovered PSK (`../psk_candidate.bin`) is the genuine TLS-PSK key.
- The MCU runs the channel for a non-SGX host → no hardware attestation required (GO).
- Layers 1–4 are implemented and working against real hardware.

## Files
- gxbridge.py  — brings up the TLS-PSK channel (the milestone PoC)
- gx_proto.py  — framing codec
- trigger.pkl  — the 12-command secure-session trigger (verbatim from capture)

## Run
Detach the reader from the VM so Linux owns it, then: `sudo python3 gxbridge.py`

## Next steps
1. Over the live channel, reverse the in-TLS app protocol: send the captured
   post-handshake commands (0x90 …) and the finger-capture request; receive the
   image app-data; work out enroll/verify. Everything now decrypts because we hold
   the session keys.
2. Reverse from-scratch provisioning (force re-pair, capture) so the driver mints its
   own PSK — makes it work on any unit, not just this one. (Destructive-ish: needs a nod.)
3. Wrap as a libfprint driver.
