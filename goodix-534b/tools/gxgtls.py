#!/usr/bin/env python3
"""Test the goodix-fp-linux-dev GTLS/PSK approach on the 534b.
Uses their message framing (cmd=cat<<4|command<<1, size16, payload, cksum=0xAA-sum),
GTLS handshake (0xFF01/02/03/04) and TLS-PRF session-key derivation."""
import sys, struct, hashlib, hmac as pyhmac, time, usb.core, usb.util

VID, PID = 0x27C6, 0x534B
EP_OUT, EP_IN = 0x01, 0x83
CHUNK = 0x40

class Dev:
    def __init__(self):
        self.d = usb.core.find(idVendor=VID, idProduct=PID)
        if not self.d: sys.exit("device not found")
        try: self.d.set_configuration()
        except usb.core.USBError: pass
        usb.util.claim_interface(self.d, 0)
        self._drain()
    def _drain(self):
        for _ in range(20):
            try: self.d.read(EP_IN, 0x1000, timeout=80)
            except usb.core.USBError: return
    def _wr(self, data):
        if len(data) % CHUNK: data += b"\x00"*(CHUNK - len(data)%CHUNK)
        for i in range(0, len(data), CHUNK):
            self.d.write(EP_OUT, data[i:i+CHUNK], timeout=2000)
    def _rd_chunk(self, timeout=2000):
        for _ in range(12):
            b = bytes(self.d.read(EP_IN, 0x1000, timeout=timeout))
            if b: return b
        raise Exception("empty reads")
    def send(self, cat, cmd, payload, use_cksum=True):
        cb = cat << 4 | cmd << 1
        data = struct.pack("<B", cb) + struct.pack("<H", len(payload)+1) + payload
        data += struct.pack("<B", (0xAA - sum(data)) & 0xFF if use_cksum else 0x88)
        # chunked send: continuation chunks prefix cb|1
        first = True; d = data
        while d:
            if first: chunk = d[:CHUNK]; d = d[CHUNK:]; first = False
            else: chunk = struct.pack("<B", cb|1) + d[:CHUNK-1]; d = d[CHUNK-1:]
            self._wr(chunk)
        self._check_ack(cb)
    def _recv(self, timeout=2000):
        data = self._rd_chunk(timeout)
        cb = data[0]; size = struct.unpack("<H", data[1:3])[0]
        while len(data)-1 < size:
            c = self._rd_chunk(timeout)
            if c[0] & 1 == 0 or c[0] & 0xFE != cb: raise Exception("bad contd chunk")
            data += c[1:]
        cat = cb >> 4; cmd = (cb & 0xF) >> 1
        data = data[:size+3]; ck = data[-1]; data = data[:-1]
        payload = data[3:]
        return cat, cmd, payload
    def _check_ack(self, cb):
        cat, cmd, pl = self._recv()
        if cat != 0xB: raise Exception("not ACK, got cat=0x%x cmd=%d pl=%s" % (cat,cmd,pl[:8].hex()))

def prf(psk, seed_random, n):
    seed = b"master secret" + seed_random
    out = b""; A = seed
    while len(out) < n:
        A = pyhmac.new(psk, A, hashlib.sha256).digest()
        out += pyhmac.new(psk, A+seed, hashlib.sha256).digest()
    return out[:n]

def production_read(dev, rtype):
    dev.send(0xE, 2, struct.pack("<L", rtype))
    cat, cmd, pl = dev._recv()
    if cat != 0xE or cmd != 2: raise Exception("not prod-read reply: %x/%d" % (cat,cmd))
    if pl[0] != 0: raise Exception("prod-read MCU failed status=%d" % pl[0])
    pl = pl[1:]; rt = struct.unpack("<L", pl[:4])[0]; pl = pl[4:]
    ln = struct.unpack("<L", pl[:4])[0]; pl = pl[4:]
    return pl

def main():
    dev = Dev()
    print("[*] reset...");
    try: dev.send(0xA, 1, (0b001 | 0b100 | (20<<8)).to_bytes(2,"little")); dev._recv()
    except Exception as e: print("   reset:", e)
    try:
        dev.send(0xA, 4, b"\x00\x00"); cat,cmd,pl = dev._recv()
        print("[*] firmware:", pl.split(b'\x00')[0].decode(errors='replace'))
    except Exception as e: print("   fw read:", e)
    # PSK hash
    try:
        h = production_read(dev, 0xB003)
        print("[*] device PSK hash:", h.hex())
        print("    SHA256(all-zero PSK): %s" % hashlib.sha256(bytes(32)).hexdigest())
        mine = bytes.fromhex("37bcba3cc1deec2a1cf14385485888cf802ba49a4529cf629de0b90d971d0b05")
        print("    SHA256(my extracted PSK): %s" % hashlib.sha256(mine).hexdigest())
        if h.hex() == hashlib.sha256(bytes(32)).hexdigest(): print("    >>> device uses ALL-ZERO PSK")
        elif h.hex() == hashlib.sha256(mine).hexdigest(): print("    >>> device PSK hash == SHA256(my extracted 32B)")
        else: print("    >>> device PSK is something else")
    except Exception as e: print("   psk hash read failed:", e)
    usb.util.release_interface(dev.d, 0)

if __name__ == "__main__":
    main()
