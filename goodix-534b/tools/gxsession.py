#!/usr/bin/env python3
"""Goodix 534b: full session driver. Handshake -> setup -> capture a frame,
receiving the encrypted image over TLS and decrypting it with our session keys.

Sensor is the TLS client; we are the PSK server. Control commands are plaintext
(A0 framing); the fingerprint image comes back as a TLS application_data record
(17 03 03) wrapped in a 13-byte B2 large-transfer header."""
import sys, os, ssl, pickle, time, usb.core, usb.util

PSK = bytes.fromhex("37bcba3cc1deec2a1cf14385485888cf802ba49a4529cf629de0b90d971d0b05")
HERE = os.path.dirname(os.path.abspath(__file__))
TRIGGER = pickle.load(open(os.path.join(HERE, "trigger.pkl"), "rb"))
SETUP   = pickle.load(open(os.path.join(HERE, "setup.pkl"), "rb"))
EP_OUT, EP_IN = 0x01, 0x83

def hdrsum(magic, ln): return (magic + (ln & 0xFF) + ((ln >> 8) & 0xFF)) & 0xFF
def wrap_b0(rec):
    ln = len(rec)
    return bytes([0xB0, ln & 0xFF, (ln >> 8) & 0xFF, hdrsum(0xB0, ln)]) + rec
def split_records(blob):
    out = []; i = 0
    while i + 5 <= len(blob):
        rl = blob[i+3] << 8 | blob[i+4]
        out.append(blob[i:i+5+rl]); i += 5 + rl
    return out

class Dev:
    def __init__(self):
        self.d = usb.core.find(idVendor=0x27C6, idProduct=0x534B)
        if self.d is None: sys.exit("device not found (detach from VM first)")
        try: self.d.set_configuration()
        except usb.core.USBError: pass
        usb.util.claim_interface(self.d, 0)
    def send(self, pkt):
        if len(pkt) < 64: pkt = pkt + b"\x00"*(64-len(pkt))
        for i in range(0, len(pkt), 64): self.d.write(EP_OUT, pkt[i:i+64], timeout=3000)
    def read_raw(self, n=16384, timeout=3000):
        return bytes(self.d.read(EP_IN, n, timeout=timeout))
    def read_frame(self, timeout=3000):
        buf = self.read_raw(64, timeout)
        if not buf: return None, b""
        if buf[0] in (0xA0, 0xB0):
            ln = buf[1] | buf[2] << 8; total = 4 + ln
            while len(buf) < total: buf += self.read_raw(64, timeout)
            return buf[0], buf[4:total]
        return buf[0], buf   # B2 or unknown: hand back raw

def do_handshake(dev):
    first_tls = None
    for cmd in TRIGGER:
        dev.send(cmd)
        try:
            magic, pl = dev.read_frame(2500)
            if magic == 0xB0 and pl[:1] == b'\x16':
                first_tls = pl; break
        except usb.core.USBError:
            pass
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try: ctx.set_ciphers("PSK-AES128-CBC-SHA256:@SECLEVEL=0")
    except ssl.SSLError: pass
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ctx.set_psk_server_callback(lambda ident: PSK, identity_hint=None)
    inbio, outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
    s = ctx.wrap_bio(inbio, outbio, server_side=True)
    if first_tls: inbio.write(first_tls)
    for _ in range(60):
        try:
            s.do_handshake()
            print("[+] TLS up: %s %s" % (s.cipher(), s.version()))
            # drain any final handshake output to the device
            out = outbio.read()
            for rec in split_records(out): dev.send(wrap_b0(rec))
            # CRITICAL (from goodix-fp-linux-dev): tell the device TLS is established (0xD4)
            from gx_proto import frame as _frame
            dev.send(_frame(0xD4, b"\x00\x00"))
            try: dev.read_frame(1500)   # ack
            except usb.core.USBError: pass
            print("[+] sent 0xD4 TLS-successfully-established")
            return s, inbio, outbio
        except ssl.SSLWantReadError:
            for rec in split_records(outbio.read()): dev.send(wrap_b0(rec))
            try: magic, pl = dev.read_frame(3000)
            except usb.core.USBError: continue
            if magic == 0xB0: inbio.write(pl)
        except ssl.SSLWantWriteError:
            for rec in split_records(outbio.read()): dev.send(wrap_b0(rec))
    raise RuntimeError("handshake did not converge")

def drain(dev, label, tries=4):
    """read plaintext ACK/data responses after a command"""
    got = []
    for _ in range(tries):
        try: magic, pl = dev.read_frame(1500)
        except usb.core.USBError: break
        if magic == 0xA0: got.append(pl)
        else: break
    if got:
        print("    %s: %d resp, first=%s" % (label, len(got), got[0][:16].hex()))
    return got

def assemble_image(dev, s, inbio, first_chunk):
    """given the first B2 chunk, read the rest, decrypt the inner TLS record."""
    buf = first_chunk
    while len(buf) < 18: buf += dev.read_raw(4096, 4000)
    reclen = buf[16] << 8 | buf[17]          # TLS record length (BE) at offset 16
    total = 13 + 5 + reclen                   # 13B B2 hdr + 5B TLS hdr + payload
    while len(buf) < total:
        buf += dev.read_raw(total - len(buf) + 64, 4000)
    tls_rec = buf[13:total]
    inbio.write(tls_rec)
    plain = s.read(reclen + 64)
    print("    [+] image: B2 %dB -> TLS rec %dB -> decrypted %dB" %
          (len(buf), len(tls_rec), len(plain)))
    return plain

def xfer(dev, cmd, want_image=False, idle=600):
    """send a command, drain ALL responses until idle (keeps pipeline synced).
    returns (list_of_a0_payloads, image_first_chunk_or_None)."""
    dev.send(cmd)
    a0 = []; img = None
    while True:
        try: m, p = dev.read_frame(idle)
        except usb.core.USBError: break     # idle -> responses done
        if m == 0xB2:
            if want_image: img = p; break
        elif m == 0xA0:
            a0.append(p)
    return a0, img

def fdt_touch(a0):
    """given A0 responses, return the FDT touch level from a 0x32/0x34 data frame
    (a02000c0 321d0002 00XXYY..); high value == finger down."""
    lvl = 0
    for p in a0:
        if p[:1] in (b'\x32', b'\x34') and len(p) > 8 and p[1] == 0x1d:
            # data frame: subcmd,1d,00,02,00, then u16 samples
            for i in range(5, min(len(p)-1, 21), 2):
                v = p[i] << 8 | p[i+1]
                if v > lvl: lvl = v
    return lvl

def capture_loop(dev, s, inbio, caps, seconds=45):
    """Correct FDT flow (from dynamic trace): arm FDT-down mode (0x32) with NO finger to
    set the baseline; poll until the device reports a finger-DOWN transition; only THEN
    send 0x20 to retrieve the image (over TLS). Sending 0x20 before a down-transition -> d0."""
    ARM_UP = bytes.fromhex("a00700a7ae0400010101f5")
    IMG    = bytes.fromhex("a00e00ae200b00050000000000000000007a")
    # Phase A: establish FDT baseline with NO finger (switch to FDT-down mode a few times)
    print("    [phase A] establishing FDT baseline (DO NOT TOUCH)...")
    base = 0
    for _ in range(6):
        a0, _ = xfer(dev, caps[0x34]); xfer(dev, ARM_UP)
        a0b, _ = xfer(dev, caps[0x32])
        base = max(base, fdt_touch(a0b))
        time.sleep(0.2)
    thr = max(base + 0x300, 0x600)
    print("    [phase A] baseline=0x%04x  finger-threshold=0x%04x" % (base, thr))
    print("    [phase B] >>> TOUCH NOW <<< waiting for finger-down transition...")
    t_end = time.time() + seconds; it = 0; peak = 0
    while time.time() < t_end:
        it += 1
        a0, _ = xfer(dev, caps[0x32])          # FDT-down poll
        lvl = fdt_touch(a0)
        if lvl > peak: peak = lvl
        if lvl >= thr:                          # finger-down detected
            print("    [it %d] finger DOWN (lvl=0x%04x) -> fetch image" % (it, lvl))
            a0, img = xfer(dev, IMG, want_image=True)
            if img is not None:
                print("    [+] IMAGE received!")
                return assemble_image(dev, s, inbio, img)
            # not ready this instant; re-arm and keep polling while finger held
            xfer(dev, caps[0x34]); xfer(dev, ARM_UP)
        time.sleep(0.03)
    print("    [!] no image in %d polls. baseline=0x%04x peak=0x%04x thr=0x%04x"
          % (it, base, peak, thr))
    return None

def main():
    dev = Dev()
    s, inbio, outbio = do_handshake(dev)
    print("[*] replaying %d setup commands..." % len(SETUP))
    for m in SETUP:
        dev.send(m); drain(dev, "setup 0x%02x" % m[4])
    # capture: 0x60 begin, then poll arm(0xAE)->frame(0x32)->fetch(0x20) cycles
    caps = pickle.load(open(os.path.join(HERE, "capcmds.pkl"), "rb"))
    BEGIN = bytes.fromhex("a00600a6600300010046")
    print("[*] begin: 0x60"); dev.send(BEGIN); drain(dev, "0x60")
    print("[*] capture loop (arm->frame->fetch)...")
    img = capture_loop(dev, s, inbio, caps, seconds=35)
    if img:
        path = os.path.join(HERE, "frame_%d.bin" % int(time.time()))
        open(path, "wb").write(img)
        print("[+] saved decrypted frame: %s (%d bytes)" % (path, len(img)))
    usb.util.release_interface(dev.d, 0)

if __name__ == "__main__":
    sys.exit(main())
