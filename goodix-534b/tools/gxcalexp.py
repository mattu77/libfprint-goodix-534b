#!/usr/bin/env python3
"""Baseline-capture experiment: which no-finger path yields a real frame that
correlates with the finger frame? Saves every frame to exp/<label>.bin."""
import sys, os, time, pickle, usb.core
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gxsession as G
from gx_proto import frame
from gxcal import parse_adc
from gxfinal import cmd

OUT = os.path.join(G.HERE, "exp"); os.makedirs(OUT, exist_ok=True)
IMG = bytes.fromhex("05000000000000000000")

def grab(dev, s, inbio, label):
    a0, img = cmd(dev, 0x20, IMG, "get_img", tries=4)
    if not img:
        print("    %-16s -> no image (%s)" % (label, "d0" if any(p[:1]==b'\xd0' for p in a0) else "acks:%d"%len(a0)))
        return None
    plain = G.assemble_image(dev, s, inbio, img)
    if plain:
        open(os.path.join(OUT, label + ".bin"), "wb").write(plain)
        print("    %-16s -> saved %dB nz=%d" % (label, len(plain), sum(1 for b in plain if b)))
    return plain

def send_raw(dev, pkt, reads=2, t=1200):
    dev.send(pkt)
    for _ in range(reads):
        try: dev.read_frame(t)
        except usb.core.USBError: break

def main():
    dev = G.Dev()
    s, inbio, outbio = G.do_handshake(dev)
    caps = pickle.load(open(os.path.join(G.HERE, "capcmds.pkl"), "rb"))
    cmd(dev, 0xAE, b"\x00\x00", "0xAE")
    send_raw(dev, next(m for m in G.SETUP if m[4] == 0x36))
    print("[*] NO-FINGER baselines (do not touch)")
    for rep in (1, 2):
        send_raw(dev, caps[0x34]); cmd(dev, 0x50, IMG, "nav0")
        grab(dev, s, inbio, "A_up_nav0_%d" % rep)
    for rep in (1, 2):
        send_raw(dev, caps[0x34])
        grab(dev, s, inbio, "B_up_%d" % rep)
    for rep in (1, 2):
        send_raw(dev, caps[0x34]); cmd(dev, 0x50, b"\x01\x00", "nav0")
        grab(dev, s, inbio, "D_up_nav0s_%d" % rep)
    for rep in (1, 2):
        send_raw(dev, caps[0x32])          # fdt-down mode, finger absent
        grab(dev, s, inbio, "C_down_%d" % rep)
    print("[*] >>> TOUCH & HOLD the sensor now <<<")
    t_end = time.time() + 35; got = 0
    while time.time() < t_end and got < 3:
        dev.send(caps[0x32])
        try: dev.read_frame(800)
        except usb.core.USBError: pass
        finger = False
        try:
            m, p = dev.read_frame(1500)
            if m == 0xA0 and p[:1] == b'\x32' and p[1] == 0x1d:
                adc = parse_adc([p]) or []
                finger = bool(adc) and max(adc[:12]) > 0x600
        except usb.core.USBError: pass
        if not finger: continue
        got += 1
        grab(dev, s, inbio, "F_finger_%d" % got)
        if got < 3: send_raw(dev, caps[0x34], reads=1, t=600)
    print("[*] lift finger; post-finger baselines")
    time.sleep(2.5)
    send_raw(dev, caps[0x34]); grab(dev, s, inbio, "E_up_after")
    send_raw(dev, caps[0x32]); grab(dev, s, inbio, "E_down_after")
    print("[done]")

if __name__ == "__main__":
    main()
