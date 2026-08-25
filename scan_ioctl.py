#!/usr/bin/env python3
"""
scan_ioctl.py - extract the real netsmb ioctl struct sizes from macOS
system binaries, by decoding the ioctl command constants they contain.

The ioctl cmd encoding (BSD):  cmd = inout | (group<<8) | num | (len<<16)
  SMBIOC_NEGOTIATE     (_IOWR 'n' 109):  0xC0000000 | (len<<16) | 0x6E6D
  SMBIOC_SSNSETUP      (_IOW  'n' 110):  0x80000000 | (len<<16) | 0x6E6E
  SMBIOC_TCON          (_IOWR 'n' 111):  0xC0000000 | (len<<16) | 0x6E6F
  SMBIOC_VC_PROPERTIES (_IOWR 'n' 116):  0xC0000000 | (len<<16) | 0x6E74
  SMB2IOC_CREATE       (_IOWR 'n' 120):  0xC0000000 | (len<<16) | 0x6E78

Running on macOS:  python3 scan_ioctl.py
"""
import struct, sys

TARGETS = [
    "/sbin/mount_smbfs",
    "/usr/bin/smbutil",
    "/usr/lib/libsmbclient.dylib",
    "/System/Library/CoreServices/NetAuthSysAgent.app/Contents/MacOS/NetAuthSysAgent",
    "/System/Library/PrivateFrameworks/NetFS.framework/Versions/A/NetFS",
    "/System/Library/Filesystems/smbfs.fs/Contents/MacOS/mount_smbfs",
    "/usr/sbin/mount_smbfs",
]

# low-16-bit marker -> (name, expected top bits 0x80000000 mask, inout bits)
MARKERS = [
    (0x6E6D, "SMBIOC_NEGOTIATE", 0xC0000000),
    (0x6E6E, "SMBIOC_SSNSETUP",  0x80000000),
    (0x6E6F, "SMBIOC_TCON",      0xC0000000),
    (0x6E74, "SMBIOC_VC_PROPERTIES", 0xC0000000),
    (0x6E78, "SMB2IOC_CREATE",   0xC0000000),
]

def scan(path):
    try:
        data = open(path, "rb").read()
    except Exception as e:
        print(f"  [skip] {path}: {e}")
        return
    hits = {}
    for low16, name, inout in MARKERS:
        hits[name] = set()
        # search all 4-byte-aligned little-endian u32 values
        for off in range(0, len(data) - 3, 4):
            v = struct.unpack_from("<I", data, off)[0]
            if (v & 0xFFFF) == low16 and (v & 0xC0000000) == (inout & 0xC0000000):
                ln = (v >> 16) & 0x1FFF
                hits[name].add(ln)
    nonempty = {k: v for k, v in hits.items() if v}
    if not nonempty:
        return
    print(f"== {path} ==")
    for name, lens in nonempty.items():
        print(f"   {name}: sizeof = {sorted(lens)}")

found_any = False
for p in TARGETS:
    scan(p)
    found_any = True

print()
print("If all sizes print as the same value for a given struct, that is the")
print("kernel's real size. Compare with the trigger's fallback layouts:")
print("  negotiate 528, setup 336, share 160, create 136, vc_properties 576")