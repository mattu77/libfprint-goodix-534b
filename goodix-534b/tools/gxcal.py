#!/usr/bin/env python3
"""Goodix 534b: DAC calibration + capture (implements the live loop from the trace).
0x32/0x34 payloads carry 12 per-column DAC values at byte offsets 18,20,..,40 (0x80XX),
checksum at byte 54. Their responses (a020..321d0002..) carry 12 BE u16 column readings.
Calibrate the DACs so readings hit the target band, then 0x20 returns the image."""
import sys, os, time, struct, usb.core, usb.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gxsession as G

DAC_OFF = list(range(18, 41, 2))   # 12 low-byte offsets in the 55-byte cmd frame

def set_dac(cmd, dacs):
    """return a copy of cmd (bytes) with the 12 DAC low-bytes set + checksum fixed."""
    b = bytearray(cmd)
    for off, v in zip(DAC_OFF, dacs):
        b[off] = v & 0xFF
        b[off-1] = 0x80
    # recompute payload checksum at byte 54 = (0xAA - sum(payload[4:54])) & 0xff
    s = sum(b[4:54]) & 0xFF
    b[54] = (0xAA - s) & 0xFF
    return bytes(b)

def get_dac(cmd):
    return [cmd[o] for o in DAC_OFF]

def parse_adc(a0):
    """from A0 responses find the 0x32/0x34 data frame and return 12 BE u16 readings."""
    for p in a0:
        if p[:1] in (b'\x32', b'\x34') and len(p) >= 4 and p[1] == 0x1d:
            data = p[3:]              # after subcmd,1d,00  -> 02 00 <readings...>
            # skip the 2-byte status (02 00), then u16 BE readings
            vals = []
            d = data[2:]
            for i in range(0, len(d)-1, 2):
                vals.append(d[i] << 8 | d[i+1])
            return vals
    return None

def main():
    dev = G.Dev()
    s, inbio, outbio = G.do_handshake(dev)
    for m in G.SETUP: dev.send(m); G.drain(dev, "s%02x" % m[4])
    import pickle
    caps = pickle.load(open(os.path.join(G.HERE, "capcmds.pkl"), "rb"))
    dev.send(bytes.fromhex("a00600a6600300010046")); G.drain(dev, "0x60")  # begin

    cap32 = caps[0x32]
    print("[*] baseline DACs in captured 0x32:", [hex(x) for x in get_dac(cap32)])
    print("[*] DAC->ADC mapping probe (no finger). columns readings per uniform DAC:")
    for dacv in (0x60, 0x80, 0xa0, 0xc0, 0xe0):
        cmd = set_dac(cap32, [dacv]*12)
        a0, _ = G.xfer(dev, cmd)
        adc = parse_adc(a0)
        if adc:
            print("   DAC=0x%02x -> ADC[0..11]= %s" % (dacv, " ".join("%4d"%v for v in adc[:12])))
        else:
            print("   DAC=0x%02x -> no ADC frame (resp: %s)" % (dacv, [p[:6].hex() for p in a0]))
        time.sleep(0.1)
    usb.util.release_interface(dev.d, 0)

if __name__ == "__main__":
    sys.exit(main())
