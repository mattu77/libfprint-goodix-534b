#!/usr/bin/env python3
"""Collect N separate touches (param-05 frames) plus the stored calibration frame
(param 01) for offline matcher tuning. Saves exp/collect/*.npy."""
import sys, os, time, pickle, usb.core
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gxsession as G
from gx_proto import frame
from gxfinal import decode12, cmd, fdt_parse

OUT = os.path.join(G.HERE, "exp", sys.argv[2] if len(sys.argv) > 2 else "collect"); os.makedirs(OUT, exist_ok=True)
P05 = bytes.fromhex("05000000000000000000"); P01 = bytes.fromhex("01000000000000000000")
N = int(sys.argv[1]) if len(sys.argv) > 1 else 6

def raw(dev, pkt, n=2, t=1200):
    dev.send(pkt)
    for _ in range(n):
        try: dev.read_frame(t)
        except usb.core.USBError: break

def grab(dev, s, inbio, body):
    a0, img = cmd(dev, 0x20, body, "img", tries=4)
    if not img: return None
    plain = G.assemble_image(dev, s, inbio, img)
    return decode12(plain) if plain else None

def fdt_state(dev, caps, t=400):
    dev.send(caps[0x32])
    try: dev.read_frame(800)
    except usb.core.USBError: pass
    try:
        m, p = dev.read_frame(t)
        if m == 0xA0 and p[:1] == b'\x32':
            r = fdt_parse(p); return r[0] if r else None
    except usb.core.USBError: pass
    return None

def main():
    dev = G.Dev(); s, inbio, outbio = G.do_handshake(dev)
    caps = pickle.load(open(os.path.join(G.HERE, "capcmds.pkl"), "rb"))
    raw(dev, frame(0xAE, b"\x00\x00")); raw(dev, next(m for m in G.SETUP if m[4] == 0x36)); raw(dev, caps[0x34])
    base = grab(dev, s, inbio, P01)
    print("[*] calibration frame std %.0f" % base.std()); np.save(os.path.join(OUT, "baseline.npy"), base)
    for k in range(N):
        print("[*] touch %d/%d: >>> TOUCH <<<" % (k + 1, N))
        while fdt_state(dev, caps, 300) is not True: pass
        f1 = grab(dev, s, inbio, P05)
        raw(dev, caps[0x34], n=2, t=600)
        f2 = grab(dev, s, inbio, P05) if fdt_state(dev, caps) is True else None
        fr = f2 if f2 is not None else f1
        np.save(os.path.join(OUT, "touch_%d.npy" % k), fr)
        print("    saved touch_%d (std %.0f)  >>> LIFT <<<" % (k, fr.std()))
        clear = 0
        while clear < 2:
            raw(dev, caps[0x34], n=2, t=600)
            clear = clear + 1 if fdt_state(dev, caps) is not True else 0
        time.sleep(0.3)
    print("[done]")

if __name__ == "__main__":
    main()
