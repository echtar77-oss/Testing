#!/usr/bin/env python3
"""Check built .ko files against the running tablet kernel.

usage: check_ath9k.py ksyms.txt known_crcs.txt ath.ko ath9k_hw.ko ath9k_common.ko ath9k_htc.ko

 1. NAME check: every symbol a module needs must be exported by your kernel
    (ksyms.txt), by cfg80211/mac80211 (also in ksyms.txt), or by another
    module in the set you pass in.
 2. CRC check: every import whose CRC is in known_crcs.txt must match it.
    A mismatch means the build headers/config differ from the tablet's.
    module_layout mismatching means wrong source commit, toolchain or config.
"""
import struct, sys

def sections(d):
    shoff = struct.unpack('<Q', d[0x28:0x30])[0]
    shentsize, shnum, shstrndx = struct.unpack('<HHH', d[0x3A:0x40])
    secs = []
    for i in range(shnum):
        o = shoff + i * shentsize
        name, typ, flags, addr, off, size, link, info, align, ent = struct.unpack('<IIQQQQIIQQ', d[o:o+64])
        secs.append((name, typ, off, size, link))
    stro = secs[shstrndx][2]
    def nm(i):
        return d[stro+i:d.index(b'\0', stro+i)].decode()
    return [(nm(s[0]),) + s[1:] for s in secs]

def parse(path):
    d = open(path, 'rb').read()
    secs = sections(d)
    exports, undef, imports = {}, set(), {}
    for name, typ, off, size, link in secs:
        if typ == 2:  # symtab
            stroff = secs[link][2]
            for k in range(1, size // 24):
                st_name, info, other, shndx, val, sz = struct.unpack('<IBBHQQ', d[off+k*24:off+k*24+24])
                s = d[stroff+st_name:d.index(b'\0', stroff+st_name)].decode()
                if not s:
                    continue
                if s.startswith('__crc_'):
                    exports[s[6:]] = val & 0xffffffff
                elif shndx == 0 and (info >> 4) in (1, 2):  # undefined, global/weak
                    undef.add(s)
        elif name == '__versions':
            for k in range(size // 64):
                crc = struct.unpack('<Q', d[off+k*64:off+k*64+8])[0] & 0xffffffff
                imports[d[off+k*64+8:off+k*64+64].split(b'\0')[0].decode()] = crc
    return exports, undef, imports

def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    ksyms = set(open(sys.argv[1]).read().split())
    known = {}
    for line in open(sys.argv[2]):
        p = line.split()
        if len(p) == 2:
            known[p[0]] = int(p[1], 16)
    mods = {m: parse(m) for m in sys.argv[3:]}
    in_set = {}
    for exp, _, _ in mods.values():
        in_set.update(exp)
    bad = 0
    for m, (exp, undef, imports) in mods.items():
        missing = sorted(s for s in undef if s not in ksyms and s not in in_set)
        crc_bad = sorted(s for s, c in imports.items()
                         if (s in known and known[s] != c) or (s in in_set and in_set[s] != c))
        checked = sum(1 for s in imports if s in known or s in in_set)
        print(f'{m}: {len(undef)} imports, {len(missing)} NOT exported, '
              f'{checked} CRCs checked, {len(crc_bad)} mismatched')
        for s in missing:
            print('   NOT EXPORTED:', s)
        for s in crc_bad:
            print('   CRC MISMATCH:', s)
        bad += len(missing) + len(crc_bad)
    print('RESULT:', 'PASS - modules should load' if bad == 0 else f'FAIL - {bad} problem(s)')
    sys.exit(1 if bad else 0)

main()
