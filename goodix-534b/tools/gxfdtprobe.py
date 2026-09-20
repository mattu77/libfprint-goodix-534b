#!/usr/bin/env python3
"""Timed FDT probe: prints every 0x32 poll (flags + mean column reading) with prompts at
fixed times so frames can be aligned with finger on/off."""
import sys, os, time, pickle, usb.core
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gxsession as G
from gx_proto import frame
from gxfinal import fdt_parse

SCHEDULE = [(0, "OFF"), (10, ">>> TOUCH & HOLD <<<"), (22, ">>> LIFT (off) <<<"), (34, ">>> TOUCH & HOLD <<<"), (46, ">>> LIFT (off) <<<"), (56, "end")]

def main():
    dev = G.Dev()
    s, inbio, outbio = G.do_handshake(dev)
    caps = pickle.load(open(os.path.join(G.HERE, "capcmds.pkl"), "rb"))
    dev.send(frame(0xAE, b"\x00\x00"))
    try: dev.read_frame(1200)
    except usb.core.USBError: pass
    dev.send(next(m for m in G.SETUP if m[4] == 0x36))
    try: dev.read_frame(1200)
    except usb.core.USBError: pass
    t0 = time.time(); step = 0
    while True:
        t = time.time() - t0
        if step < len(SCHEDULE) and t >= SCHEDULE[step][0]:
            print("=== t=%2.0f  %s" % (t, SCHEDULE[step][1])); step += 1
            if SCHEDULE[step-1][1] == "end": break
        dev.send(caps[0x34])
        try: dev.read_frame(600)
        except usb.core.USBError: pass
        dev.send(caps[0x32])
        got = []
        for _ in range(3):
            try:
                m, p = dev.read_frame(700); got.append((m, p))
            except usb.core.USBError:
                break
        desc = []
        for m, p in got:
            if m == 0xA0 and p[:1] == b'\x32':
                r = fdt_parse(p)
                desc.append("data flags=%s mean=0x%03x" % (p[5:7].hex(), sum(r[1]) // 12) if r else "data?")
            elif m == 0xA0:
                desc.append("a0:%s" % p[:2].hex())
            else:
                desc.append("m=%02x" % m)
        print("  t=%4.1f  %s" % (t, "  ".join(desc) if desc else "(no response)"))
        time.sleep(0.25)

if __name__ == "__main__":
    main()
