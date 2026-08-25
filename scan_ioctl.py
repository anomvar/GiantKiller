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
import os, shutil, struct, sys

TARGETS = [
    "/sbin/mount_smbfs",
    "/usr/bin/smbutil",
    "/usr/sbin/mount_smbfs",
    "/usr/lib/libsmbclient.dylib",
    "/System/Library/CoreServices/NetAuthSysAgent.app/Contents/MacOS/NetAuthSysAgent",
    "/System/Library/PrivateFrameworks/NetFS.framework/Versions/A/NetFS",
    "/System/Library/Filesystems/smbfs.fs/Contents/MacOS/mount_smbfs",
]

def locate():
    found = []
    for cmd in ("smbutil", "mount_smbfs"):
        p = shutil.which(cmd)
        if p:
            found.append(p)
    for base in ("/usr/bin", "/usr/sbin", "/sbin", "/bin",
                 "/System/Library/CoreServices",
                 "/System/Library/PrivateFrameworks",
                 "/System/Library/Filesystems"):
        if os.path.isdir(base):
            for root, dirs, files in os.walk(base):
                # keep it shallow
                if root.count(os.sep) - base.count(os.sep) > 4:
                    dirs[:] = []
                    continue
                for f in files:
                    if f in ("smbutil", "mount_smbfs", "libsmbclient.dylib",
                             "NetAuthSysAgent", "NetFS", "smbfs"):
                        found.append(os.path.join(root, f))
    return found

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
paths = list(TARGETS) + locate()
seen = set()
for p in paths:
    p = os.path.realpath(p)
    if p in seen:
        continue
    seen.add(p)
    scan(p)
    found_any = True

print()
try:
    ver = os.popen("sw_vers -productVersion").read().strip()
    print("macOS version:", ver)
except Exception:
    pass
print("If all sizes print as the same value for a given struct, that is the")
print("kernel's real size. Compare with the trigger's fallback layouts:")
print("  negotiate 528, setup 336, share 160, create 136, vc_properties 576")