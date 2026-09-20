#!/usr/bin/env python3
"""Test goodix GTLS handshake (0xFF01/02/03/04) on the 534b using OUR proven framing
(gx_proto). GTLS msgs ride on subcmd 0xD2 = Message(cat=0xD,cmd=1). Session key via
TLS-PRF from the PSK; mutual HMAC identity confirmation."""
import sys, os, struct, hashlib, hmac as pyhmac, time, usb.core, usb.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gx_proto import frame, ck
import gxsession as G

PSK_MINE = bytes.fromhex("37bcba3cc1deec2a1cf14385485888cf802ba49a4529cf629de0b90d971d0b05")
PSK_ZERO = bytes(32)

def prf(psk, rand, n):
    seed = b"master secret" + rand
    out = b""; A = seed
    while len(out) < n:
        A = pyhmac.new(psk, A, hashlib.sha256).digest()
        out += pyhmac.new(psk, A+seed, hashlib.sha256).digest()
    return out[:n]

def gtls_send(dev, datatype, data):
    body = struct.pack("<L", datatype) + struct.pack("<L", len(data)+8) + data
    dev.send(frame(0xD2, body))

def gtls_recv(dev, want_type, timeout=3000):
    # read frames until a 0xD2/0xD0 GTLS message; return its inner data
    for _ in range(8):
        try: magic, pl = dev.read_frame(timeout)
        except usb.core.USBError: return None
        if magic in (0xA0, 0xB0) and pl[:1] in (b'\xd2', b'\xd0'):
            inner = pl[3:-1] if len(pl) > 4 else pl
            # inner: u32 datatype, u32 len, data
            if len(inner) >= 8:
                dt = struct.unpack("<L", inner[:4])[0]
                return dt, inner[8:]
            return None, inner
        # else: ACK/other, keep reading
    return None

def try_gtls(dev, psk, label):
    print("\n=== GTLS handshake attempt with %s ===" % label)
    cr = os.urandom(0x20)
    gtls_send(dev, 0xFF01, cr)
    r = gtls_recv(dev, 0xFF02)
    if not r:
        print("   no 0xFF02 response (device didn't accept GTLS client-hello)")
        return False
    dt, data = r
    print("   got response datatype=0x%x len=%d: %s" % (dt if dt else -1, len(data), data[:32].hex()))
    if dt != 0xFF02 or len(data) < 0x40:
        print("   not a valid 0xFF02 server-identity")
        return False
    sr = data[:0x20]; server_id = data[0x20:0x40]
    sk = prf(psk, cr + sr, 0x44)
    hmac_key = sk[0x20:0x40]
    client_id = pyhmac.new(hmac_key, cr + sr, hashlib.sha256).digest()
    print("   server_identity=%s" % server_id.hex())
    print("   client_identity=%s" % client_id.hex())
    if server_id == client_id:
        print("   >>> SERVER IDENTITY MATCHES! PSK is correct, GTLS handshake valid.")
        gtls_send(dev, 0xFF03, client_id + b"\xee"*4)
        r2 = gtls_recv(dev, 0xFF04)
        print("   0xFF04 result:", r2)
        return True
    else:
        print("   server_identity != client_identity (wrong PSK for GTLS)")
        return False

def main():
    dev = G.Dev()
    # minimal init: our proven trigger up to (not incl) TLS handshake
    for cmd in G.TRIGGER[:-1]:   # skip 0xD0 (that starts the mbedTLS path)
        dev.send(cmd)
        try: dev.read_frame(1500)
        except usb.core.USBError: pass
    for psk, lbl in [(PSK_ZERO, "all-zero PSK"), (PSK_MINE, "my extracted PSK")]:
        if try_gtls(dev, psk, lbl): break
    usb.util.release_interface(dev.d, 0)

if __name__ == "__main__":
    main()
