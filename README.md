# libfprint driver for the Goodix 27c6:534b (Dell MS819 fingerprint mouse)

A working Linux driver for the Goodix fingerprint sensor built into the Dell MS819
mouse, as a fork of [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)
1.94.100. It talks the sensor's TLS-PSK protocol, captures and decrypts images, and
authenticates through fprintd with its own matcher — the sensor is far too small
(108×88 px, ≈5.4×4.4 mm) for libfprint's minutiae matcher.

Status (tested on Fedora 44, fprintd 1.94.5):

| step | result |
|---|---|
| `fprintd-enroll` (16 touches) | completes, no retries |
| `fprintd-verify`, enrolled finger | match, score ≈0.86 |
| `fprintd-verify`, other finger | no match, score ≈0.21 |
| Plasma lock screen unlock | first touch, score ≈0.73 (`kde-fingerprint` → `fingerprint-auth` → `pam_fprintd`) |
| PAM | `authselect enable-feature with-fingerprint` (Fedora) |

Everything here was reverse engineered from the Windows driver and USB captures;
nothing came from Goodix. Read the caveats below before relying on it.

## Build and install

```sh
git clone https://github.com/mattu77/libfprint-goodix-534b
cd libfprint-goodix-534b
meson setup build --prefix=/usr/local -Ddrivers=goodixtls534b \
    -Dudev_rules=disabled -Dudev_hwdb=disabled -Ddoc=false -Dinstalled-tests=false
ninja -C build
sudo ninja -C build install
```

Dependencies (Fedora names): `meson ninja-build gcc glib2-devel libgusb-devel
nss-devel pixman-devel openssl-devel gobject-introspection-devel libgudev-devel`.

Point fprintd at the private library instead of replacing the distro one:

```sh
sudo mkdir -p /etc/systemd/system/fprintd.service.d
printf '[Service]\nEnvironment=LD_LIBRARY_PATH=/usr/local/lib64\n' | \
    sudo tee /etc/systemd/system/fprintd.service.d/override.conf
sudo systemctl daemon-reload && sudo systemctl stop fprintd
fprintd-list "$USER"          # should list "Goodix TLS Fingerprint Sensor 534b"
fprintd-enroll                # 16 touches, ~1 s each, keep the finger roughly centred
fprintd-verify
sudo authselect enable-feature with-fingerprint   # PAM (Fedora)
```

On Fedora that adds `pam_fprintd` to `system-auth` and `fingerprint-auth`; the Plasma
lock screen uses the `kde-fingerprint` service on top of `fingerprint-auth`, so it picks
it up as well. Plasma Login Manager (`plasmalogin`) has no fingerprint authenticator, so
there the sensor can only sit in the sequential stack. Password first, fingerprint only
when the password is empty or wrong (a later module cannot override a failed
`password-auth` substack, hence the explicit lines and the jump), `/etc/pam.d/plasmalogin`:

```
auth  [success=done ignore=ignore default=bad] pam_selinux_permit.so
auth  required                       pam_env.so
auth  required                       pam_faildelay.so delay=2000000
auth  [success=2 default=ignore]     pam_unix.so nullok
auth  [success=done default=ignore]  pam_fprintd.so timeout=10 max-tries=1
auth  required                       pam_deny.so
-auth optional                       pam_gnome_keyring.so
-auth optional                       pam_kwallet5.so
-auth optional                       pam_kwallet.so
auth  include                        postlogin
```

A typed password logs in immediately (and unlocks KWallet); press Enter with an empty
password to get the fingerprint prompt and touch within 10 s.
Logging in by fingerprint cannot unlock KWallet, which needs the password. Without `G_MESSAGES_DEBUG=all` in the
fprintd unit override, fprintd logs nothing about verifications — add it while testing.

Without fprintd: `echo 6 | build/examples/enroll` (6 = right index) and
`build/examples/verify` store the print in `./test-storage.variant`;
`build/examples/img-capture` is not supported (this is not an image device).

## How it works

`libfprint/drivers/goodixtls/`:

- `goodix.c`, `goodixtls.c`, `goodix_proto.c` — message layer and TLS server from the
  [goodix-fp-linux-dev](https://github.com/goodix-fp-linux-dev/libfprint) `goodixtls`
  branch, ported to libfprint 1.94.100 and fixed for this device: `B2` image packs,
  several packs per USB read, per-driver PSK, a handshake that forwards each TLS
  record in its own pack and accepts any number of client packs, raw `MCU_GET_IMAGE`
  payloads. The base class is a plain `FpDevice` here, not an image device.
- `goodix534b.c/.h` — the driver: init sequence, TLS-PSK + `0xD4`, MCU config,
  finger detection by polling `0x32`, two frames per touch, ridge map = frame −
  stored calibration frame (`0x20` param `01`), 16-view enrollment, verify/identify.
  Templates are `FPI_PRINT_RAW` byte arrays: `GX534B01 | u16 n_views | u16 pixels |
  int8 views`.
- `gx534b_match.c/.h` — the matcher: band-limited phase-only correlation
  (Ito et al.). Per enrolled view and probe rotation (±12°, 3° steps): POC alignment
  on a 128×128 FFT, crop the common region, BLPOC over the lowest 35 % of the
  spectrum; the peak height is the score, threshold 0.45.

Why not NBIS: a touch of this sensor holds 2–9 real minutiae and bozorth3 needs 10;
every cross-touch score was 0, even with the minimum lowered. Plain correlation does
not separate fingers either (different fingers with parallel ridges score 0.6). BLPOC
measured on this device: same finger with overlapping placement 0.60–0.88, different
finger ≤0.29. Views that do not overlap look like impostors, which is why enrollment
asks for 16 touches with the finger roughly centred.

The protocol notes are in `goodix-534b/docs/` (`FLOW.md` is the current picture,
`RE-NOTES.md` and `CALIBRATION.md` the earlier reverse-engineering log) and the
Python tools used to get there in `goodix-534b/tools/` (`gxfinal.py` captures a
fingerprint from the command line; `gxcollect.py` collects touches for matcher
experiments).

## Bootloader (IAP) recovery

After an application crash the sensor reboots into its `MILAN_GM168SEC_IAP_10007`
bootloader and stays there (firmware version query answers, everything else times
out) until the host restores the application. The Windows driver does this by
writing a 25 KB blob in 256-byte `write_firmware` (0xf0) chunks, sending
`check_firmware` (0xf4) with a 32-byte HMAC and a soft MCU reset (0xa2, `02 32`);
both blob and HMAC are constant, so the driver replays them
(`goodix534b_recovery.h`, captured with usbmon). The sensor re-enumerates after the
reset, so the open that triggered the recovery fails with "sensor was in bootloader
mode and has been restored ... please retry" and the next open works. The reset is
fired 300 ms after that failure is reported: if the device drops off the bus while
libfprint's deferred task return is still pending, fprintd crashes (use after free
in `fp_device_task_return_in_idle_cb`). A cold plug
does not cause this; a crashed application does. The blob is Goodix's firmware data,
replayed verbatim like the firmware files in goodix-fp-dump.

## Caveats

- **The PSK.** The sensor encrypts images over TLS-PSK. The key in `goodix534b.h`
  was extracted from the Windows driver's SGX enclave on one mouse. It may be
  per-model, in which case this works on any MS819, or per-device, in which case
  other units need their own key (or a provisioning implementation — the community
  projects write a known key to the device with `PRESET_PSK_WRITE`, which is not
  done here). Reports either way are welcome.
- **The match threshold** (0.45) was validated on two fingers of one person. The
  false-accept rate at population scale is unmeasured. Treat fingerprint login as a
  convenience, not a security boundary, until more fingers have been tried against
  a template.
- Genuine matches need overlap with an enrolled view; if false rejects appear, raise
  `ENROLL_STAGES` rather than lowering the threshold.
- Matching runs synchronously inside fprintd (~0.4 s for 16 views).
- Only tested with the MS819 (27c6:534b). Other Goodix TLS sensors from the
  community project are not built by this fork.

## License

LGPL-2.1-or-later, like libfprint (see `COPYING`). The goodixtls message layer is
© 2021 Alexander Meiler, Matthieu Charette, Natasha England-Elbro; the 534b driver,
matcher, tools and notes © 2026 Mateusz Ryczko.
