#!/usr/bin/env python3
"""Goodix 534b (Dell MS819) fingerprint capture from Linux.

Sequence: TLS-PSK handshake (+0xD4 TLS_SUCCESSFULLY_ESTABLISHED) -> 0xAE -> fdt_mode (0x36)
-> loop switch_to_fdt_down (0x32) until the device reports finger-down (0x32 data frame with
high ADC) -> get_img (0x20, 10-byte body param 0x05) twice, keep the second (the first frame
after touch is still settling) -> wait for the finger to lift (ADC low) -> get_img once more
in fdt_down mode = baseline (fixed-pattern noise).

get_img returns random bytes before the first finger-down event of a session and in fdt_up
mode (measured: uniform 0..4095, zero frame-to-frame correlation), so the baseline can only be
taken after a touch. fingerprint = finger - baseline. Frame = 12-bit packed, 108x88."""
import sys, os, time, usb.core, pickle
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gxsession as G
from gx_proto import frame

W, H = 108, 88
IMG = bytes.fromhex("05000000000000000000")   # 0x20 body as sent by the Windows driver
GARBAGE_STD = 900                              # unprimed frames have std ~1180, real ~500

def cmd(dev, subcmd, body, label, tries=4):
    dev.send(frame(subcmd, body))
    a0 = []
    for _ in range(tries):
        try: m, p = dev.read_frame(1200)
        except usb.core.USBError: break
        if m == 0xA0: a0.append(p)
        elif m == 0xB2:  # image
            return a0, p
        else: break
    return a0, None

def decode12(plain):
    """12-bit packed: 6 bytes -> 4 pixels (layout from goodix-fp-linux-dev)."""
    px = []
    for i in range(0, len(plain) - 5, 6):
        c = plain[i:i+6]
        px += [((c[0] & 0xf) << 8) | c[1], (c[3] << 4) | (c[0] >> 4),
               ((c[5] & 0xf) << 8) | c[2], (c[4] << 4) | (c[5] >> 4)]
    return np.array(px[:W*H], dtype=float).reshape(H, W)

def grab(dev, s, inbio, label):
    """get_img -> decoded frame, or None if the device had no image / returned garbage."""
    a0, img = cmd(dev, 0x20, IMG, "get_img", tries=4)
    if not img:
        return None, None
    plain = G.assemble_image(dev, s, inbio, img)
    if not plain:
        return None, None
    a = decode12(plain)
    if a.std() > GARBAGE_STD:
        print("    %s: unprimed/garbage frame (std %.0f)" % (label, a.std()))
        return None, None
    return a, plain

def fdt_parse(p):
    """0x32/0x34 data frame: 32 1d 00 02 00 | flags(2) | 12 x LE u16 column readings | ck.
    flags[1] bit 2 set (ff 0f) == finger down, clear (ff 0b) == finger up."""
    if len(p) < 7 + 24 or p[1] != 0x1d:
        return None
    return bool(p[6] & 0x04), [p[7+2*i] | p[8+2*i] << 8 for i in range(12)]

def fdt_down_poll(dev, caps):
    """switch_to_fdt_down; returns True (finger down) / False (up) / None (no data frame:
    the device sends one only once a finger has been detected)."""
    dev.send(caps[0x32])
    try: dev.read_frame(800)            # ack
    except usb.core.USBError: pass
    try:
        m, p = dev.read_frame(1500)
        if m == 0xA0 and p[:1] == b'\x32':
            r = fdt_parse(p)
            return r[0] if r else None
    except usb.core.USBError:
        pass
    return None

def render(diff, path, scale=4):
    from PIL import Image
    a = diff[1:]                          # first row is always zero on this sensor
    lo, hi = np.percentile(a, 1), np.percentile(a, 99)
    a = np.clip((a - lo) / ((hi - lo) or 1), 0, 1)
    Image.fromarray((a * 255).astype("uint8"), "L").resize((W*scale, (H-1)*scale), Image.BICUBIC).save(path)

def main():
    dev = G.Dev()
    s, inbio, outbio = G.do_handshake(dev)
    caps = pickle.load(open(os.path.join(G.HERE, "capcmds.pkl"), "rb"))
    cmd(dev, 0xAE, b"\x00\x00", "0xAE")
    dev.send(next(m for m in G.SETUP if m[4] == 0x36))
    try: dev.read_frame(1200)
    except usb.core.USBError: pass
    dev.send(caps[0x34])
    try: dev.read_frame(1200)
    except usb.core.USBError: pass

    print("[*] >>> TOUCH & HOLD the sensor <<<")
    finger = None
    t_end = time.time() + 45
    while time.time() < t_end and finger is None:
        if fdt_down_poll(dev, caps) is not True:
            continue
        print("    finger down")
        first, _ = grab(dev, s, inbio, "frame1")
        dev.send(caps[0x34])
        try: dev.read_frame(600)
        except usb.core.USBError: pass
        if fdt_down_poll(dev, caps) is True:
            second, plain = grab(dev, s, inbio, "frame2")
            if second is not None:
                finger = second; print("    got finger frame (std %.0f)" % finger.std())
        if finger is None and first is not None:
            finger = first; print("    kept first frame (std %.0f)" % finger.std())
    if finger is None:
        print("[!] no finger frame"); return

    print("[*] >>> LIFT your finger <<<")
    base = None
    t0 = time.time(); t_end = t0 + 60; clear = 0; n = 0
    while time.time() < t_end and base is None:
        dev.send(caps[0x34])
        try: dev.read_frame(600)
        except usb.core.USBError: pass
        st = fdt_down_poll(dev, caps); n += 1
        if st is True and n % 8 == 0: print("    still touching...")
        clear = 0 if st is True else clear + 1
        if clear < 3:
            continue
        base, _ = grab(dev, s, inbio, "baseline")
    if base is None:
        print("[!] no baseline frame; saving raw finger frame only")
    ts = int(time.time())
    np.save(os.path.join(G.HERE, "finger_%d.npy" % ts), finger)
    if base is not None:
        np.save(os.path.join(G.HERE, "base_%d.npy" % ts), base)
        diff = finger - base
        out = os.path.join(os.path.dirname(G.HERE), "fingerprint.png")
        render(diff, out)
        print("[+] fingerprint = finger - baseline (diff std %.0f) -> %s" % (diff.std(), out))

if __name__ == "__main__":
    main()
