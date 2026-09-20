#!/usr/bin/env python3
"""Goodix 27c6:534b (Dell MS819 mouse) protocol - derived from Windows USB capture."""

def ck(d):
    return (0xAA - sum(d)) & 0xFF

def frame(subcmd, body=b""):
    """A0 | len16 | hdrsum | subcmd | inner_len16 | body | cksum
    inner_len counts body + the trailing checksum byte."""
    inner = bytes([subcmd]) + (len(body) + 1).to_bytes(2, "little") + body
    payload = inner + bytes([ck(inner)])
    hdr = bytes([0xA0]) + len(payload).to_bytes(2, "little")
    return hdr + bytes([sum(hdr) & 0xFF]) + payload

def parse(b):
    assert b[0] == 0xA0, "bad magic %02x" % b[0]
    plen = b[1] | b[2] << 8
    assert b[3] == (b[0] + b[1] + b[2]) & 0xFF, "bad header sum"
    payload = b[4:4 + plen]
    assert ck(payload[:-1]) == payload[-1], "bad payload cksum"
    return payload[0], payload[3:-1]          # subcmd, body

if __name__ == "__main__":
    # verify against bytes actually seen on the wire from Windows
    vectors = [
        ("GET_VERSION req", 0xA8, b"\x00\x00", "a00600a6a803000000ff"),
        ("cmd#1 init",      0x00, b"\x00\x00\x00\x00", "a00800a800050000000000a5"),
    ]
    for name, sub, body, expect in vectors:
        got = frame(sub, body).hex()
        print("%-16s built=%-26s capture=%-26s %s" % (name, got, expect, "MATCH" if got == expect else "DIFFER"))
    for name, h in [("ACK", "a00600a6b00300a8014e"),
                    ("VERSION", "a01d00bda81a0047465553425f474d3136385345435f4150505f31303032320070")]:
        sub, body = parse(bytes.fromhex(h))
        print("%-16s subcmd=0x%02x body=%r" % ("parse " + name, sub, body))
