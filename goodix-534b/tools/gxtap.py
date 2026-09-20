#!/usr/bin/env python3
"""Replay the exact Windows capture cycle (0x20 -> 0x34 -> 0xAE -> 0x34 -> 0x32) and
watch for the image, which arrives as a B2-wrapped TLS record on a finger-DOWN
*arrival* transition. TAP the sensor (lift+press) repeatedly, don't hold."""
import sys, os, time, usb.core, usb.util, pickle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gxsession as G
from gxcal import parse_adc

def main():
    dev = G.Dev()
    s, inbio, outbio = G.do_handshake(dev)
    for m in G.SETUP: dev.send(m); G.drain(dev, "s")
    caps = pickle.load(open(os.path.join(G.HERE, "capcmds.pkl"), "rb"))
    C32, C34 = caps[0x32], caps[0x34]
    AE  = bytes.fromhex("a00700a7ae0400010101f5")
    IMG = bytes.fromhex("a00e00ae200b00050000000000000000007a")
    dev.send(bytes.fromhex("a00600a6600300010046")); G.drain(dev, "60")
    print("[*] >>> TAP the sensor repeatedly (press ~1s, LIFT, repeat) <<<")
    t_end = time.time() + 60; it = 0; peak = 0; d0 = 0
    FAST = 150   # ms idle -> fast polling like the Windows driver
    while time.time() < t_end:
        it += 1
        a0, img = G.xfer(dev, IMG, want_image=True, idle=FAST)
        if img is not None:
            print("    [it %d] IMAGE! peak_adc=%d" % (it, peak))
            return G.assemble_image(dev, s, inbio, img)
        for p in a0:
            if p[:1] == b'\xd0': d0 += 1
        a0u, _ = G.xfer(dev, C34, idle=FAST); G.xfer(dev, AE, idle=FAST); G.xfer(dev, C34, idle=FAST)
        a0d, _ = G.xfer(dev, C32, idle=FAST)
        adc = parse_adc(a0d) or parse_adc(a0u)
        if adc:
            m = max(adc[:12]) if len(adc) >= 12 else max(adc)
            if m > peak: peak = m
        if it % 40 == 0: print("    ...%d cycles, peak_adc=%d, d0=%d" % (it, peak, d0))
    print("    [!] no image in %d cycles. peak_adc=%d d0=%d" % (it, peak, d0))
    return None

if __name__ == "__main__":
    img = main()
    if img:
        path = os.path.join(G.HERE, "frame_%d.bin" % int(time.time()))
        open(path, "wb").write(img)
        print("[+] saved decrypted frame: %s (%d bytes)" % (path, len(img)))
