#!/usr/bin/env python3
"""PoC: bring up the Goodix 534b TLS-PSK secure channel from Linux.
Replays the capture-derived trigger sequence, then bridges the sensor
(TLS client) to a Python stdlib ssl PSK *server* holding the candidate PSK.
Handshake reaching 'connected' verifies the PSK and proves the channel."""
import sys, os, ssl, pickle, usb.core, usb.util

PSK = bytes.fromhex("37bcba3cc1deec2a1cf14385485888cf802ba49a4529cf629de0b90d971d0b05")
HERE = os.path.dirname(os.path.abspath(__file__))
TRIGGER = pickle.load(open(os.path.join(HERE,"trigger.pkl"),"rb"))

EP_OUT, EP_IN = 0x01, 0x83

def hdrsum(magic, ln): return (magic + (ln & 0xFF) + ((ln>>8)&0xFF)) & 0xFF
def wrap_b0(rec):
    ln = len(rec)
    return bytes([0xB0, ln & 0xFF, (ln>>8)&0xFF, hdrsum(0xB0,ln)]) + rec

def split_records(blob):
    """split a concatenated TLS record stream into individual records"""
    out=[]; i=0
    while i+5 <= len(blob):
        rl = blob[i+3]<<8 | blob[i+4]
        out.append(blob[i:i+5+rl]); i += 5+rl
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
        for i in range(0,len(pkt),64): self.d.write(EP_OUT, pkt[i:i+64], timeout=3000)
    def read_frame(self, timeout=3000):
        buf = bytes(self.d.read(EP_IN, 64, timeout=timeout))
        if not buf or buf[0] not in (0xA0,0xB0): return buf[0] if buf else None, buf
        ln = buf[1] | buf[2]<<8; total = 4+ln
        while len(buf) < total:
            buf += bytes(self.d.read(EP_IN, 64, timeout=timeout))
        return buf[0], buf[4:total]   # magic, payload

def main():
    dev = Dev()
    print("[*] replaying %d trigger commands..." % len(TRIGGER))
    for i,cmd in enumerate(TRIGGER):
        dev.send(cmd)
        try:
            magic,pl = dev.read_frame(timeout=2500)
            tag = "TLS" if magic==0xB0 else ("ACK" if magic==0xA0 else "?")
            if magic==0xB0 and pl[:1]==b'\x16':
                print("    [%02d] -> device already speaking TLS (ClientHello)"%i); first_tls=pl; break
        except usb.core.USBError:
            pass
    else:
        first_tls=None

    # TLS-PSK server over MemoryBIO
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try: ctx.set_ciphers("PSK-AES128-CBC-SHA256:@SECLEVEL=0")
    except ssl.SSLError as e: print("cipher set warn:",e)
    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    ctx.set_psk_server_callback(lambda ident: PSK, identity_hint=None)
    inbio, outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
    sslobj = ctx.wrap_bio(inbio, outbio, server_side=True)

    if first_tls: inbio.write(first_tls)
    print("[*] bridging TLS-PSK handshake (cipher target PSK-AES128-CBC-SHA256)...")
    for step in range(60):
        try:
            sslobj.do_handshake()
            print("\n[+] HANDSHAKE COMPLETE  cipher=%s  version=%s" % (sslobj.cipher(), sslobj.version()))
            print("[+] PSK VERIFIED - the recovered key is the real TLS-PSK. Channel is live.")
            return 0
        except ssl.SSLWantReadError:
            out = outbio.read()
            for rec in split_records(out):
                dev.send(wrap_b0(rec))
            try:
                magic,pl = dev.read_frame(timeout=3000)
            except usb.core.USBError as e:
                print("    (read timeout at step %d: %s)"%(step,e)); continue
            if magic==0xB0:
                inbio.write(pl)
            elif magic==0xA0:
                pass  # stray ACK, ignore
        except ssl.SSLWantWriteError:
            out = outbio.read()
            for rec in split_records(out): dev.send(wrap_b0(rec))
        except ssl.SSLError as e:
            print("\n[-] TLS error: %s" % e)
            print("    -> PSK likely wrong OR framing/trigger mismatch (see notes).")
            return 1
    print("[-] handshake did not converge in 60 steps")
    return 1

if __name__=="__main__":
    sys.exit(main())
