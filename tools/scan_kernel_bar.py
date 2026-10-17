#!/usr/bin/env python3
"""Offline scanner for the PS5 13.60 live kernel dump.

The goal is deliberately narrow: find evidence that helps locate the /dev/bar
ioctl dispatch path without modifying a console.  The scanner searches the raw
live-memory reconstruction for:

* BAR ioctl request constants 0xc0684201 .. 0xc0684208,
* nearby occurrences of the ioctl family prefix,
* BAR/backup/restore-related ASCII strings,
* clusters of request-constant hits that are likely worth opening in Ghidra.

The public 13.60 dump currently used by this research is a flat mapping:
  file offset 0x000000 -> VA 0xffffffff9e3f0000 (kernel text)
  file offset 0xCC0000 -> VA 0xffffffff9f0b0000 (kernel data)
so for captured regions VA = TEXT_BASE + file_offset.

No kernel or BAR data is changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Iterable

TEXT_BASE = 0xFFFFFFFF9E3F0000
TEXT_SIZE = 0xCC0000
EXPECTED_SIZE = 103_546_880
EXPECTED_SHA256 = "c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd"

IOCTLS = [0xC0684200 + i for i in range(1, 9)]
STRING_NEEDLES = [
    b"/dev/bar",
    b"Backup And Restore",
    b"Backup and Restore",
    b"backup",
    b"restore",
    b"BAR",
    b"bar",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def all_hits(buf: bytes, needle: bytes, start: int = 0, end: int | None = None) -> list[int]:
    if end is None:
        end = len(buf)
    out: list[int] = []
    pos = start
    while True:
        pos = buf.find(needle, pos, end)
        if pos < 0:
            break
        out.append(pos)
        pos += 1
    return out


def va(off: int) -> int:
    return TEXT_BASE + off


def region(off: int) -> str:
    return "text" if off < TEXT_SIZE else "data"


def hexdump(buf: bytes, center: int, before: int = 0x40, after: int = 0x80) -> str:
    start = max(0, center - before)
    end = min(len(buf), center + after)
    lines: list[str] = []
    for off in range(start, end, 16):
        row = buf[off : min(off + 16, end)]
        hx = " ".join(f"{b:02X}" for b in row)
        asc = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)
        lines.append(f"0x{off:08X}  {hx:<47}  |{asc}|")
    return "\n".join(lines)


def cluster_offsets(offsets: Iterable[int], gap: int = 0x4000) -> list[list[int]]:
    vals = sorted(set(offsets))
    if not vals:
        return []
    clusters: list[list[int]] = [[vals[0]]]
    for x in vals[1:]:
        if x - clusters[-1][-1] <= gap:
            clusters[-1].append(x)
        else:
            clusters.append([x])
    return clusters


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel", type=Path, help="decompressed kernel-13.60-live.bin")
    ap.add_argument("--json", dest="json_path", type=Path, help="optional JSON result path")
    ap.add_argument("--context", type=lambda x: int(x, 0), default=0x60,
                    help="bytes before/after each ioctl hit to dump (default 0x60)")
    args = ap.parse_args()

    path: Path = args.kernel
    data = path.read_bytes()
    digest = sha256_file(path)

    print("=== PS5 13.60 /dev/bar kernel signature scan ===")
    print(f"file={path}")
    print(f"size=0x{len(data):X} ({len(data)})")
    print(f"sha256={digest}")
    if len(data) != EXPECTED_SIZE:
        print(f"WARNING: expected size {EXPECTED_SIZE} (0x{EXPECTED_SIZE:X})")
    if digest.lower() != EXPECTED_SHA256:
        print("WARNING: SHA256 does not match the published 13.60 live dump")
    else:
        print("published dump hash: MATCH")

    result: dict = {
        "file": str(path),
        "size": len(data),
        "sha256": digest,
        "text_base": f"0x{TEXT_BASE:016x}",
        "text_size": TEXT_SIZE,
        "ioctls": {},
        "strings": {},
        "clusters": [],
    }

    print("\n-- exact 32-bit ioctl constants --")
    all_ioctl_offsets: list[int] = []
    for req in IOCTLS:
        needle = struct.pack("<I", req)
        hits = all_hits(data, needle)
        all_ioctl_offsets.extend(hits)
        result["ioctls"][f"0x{req:08x}"] = [
            {"offset": h, "va": f"0x{va(h):016x}", "region": region(h)} for h in hits
        ]
        if hits:
            print(f"0x{req:08X}: {len(hits)} hit(s)")
            for h in hits:
                print(f"  off=0x{h:08X} va=0x{va(h):016X} region={region(h)}")
        else:
            print(f"0x{req:08X}: no exact hit")

    # Useful if the compiler encoded only a base/range and then indexed 1..8.
    family_needles = {
        "base_0xc0684200": struct.pack("<I", 0xC0684200),
        "first_0xc0684201": struct.pack("<I", 0xC0684201),
        "last_0xc0684208": struct.pack("<I", 0xC0684208),
        "low24_0x6842": bytes.fromhex("42 68 C0"),
    }
    print("\n-- ioctl family helper signatures --")
    result["family_signatures"] = {}
    for name, needle in family_needles.items():
        hits = all_hits(data, needle)
        result["family_signatures"][name] = [
            {"offset": h, "va": f"0x{va(h):016x}", "region": region(h)} for h in hits
        ]
        print(f"{name}: {len(hits)} hit(s)")
        for h in hits[:32]:
            print(f"  off=0x{h:08X} va=0x{va(h):016X} region={region(h)}")
        if len(hits) > 32:
            print(f"  ... {len(hits)-32} more")

    clusters = cluster_offsets(all_ioctl_offsets)
    print("\n-- clusters of exact ioctl hits (gap <= 0x4000) --")
    if not clusters:
        print("no exact-constant clusters")
    for idx, c in enumerate(clusters):
        lo, hi = min(c), max(c)
        result["clusters"].append({
            "index": idx,
            "count": len(c),
            "start_offset": lo,
            "end_offset": hi,
            "start_va": f"0x{va(lo):016x}",
            "end_va": f"0x{va(hi):016x}",
            "region": region(lo),
        })
        print(
            f"cluster[{idx}] hits={len(c)} off=0x{lo:08X}..0x{hi:08X} "
            f"va=0x{va(lo):016X}..0x{va(hi):016X} region={region(lo)}"
        )

    print("\n-- BAR/backup/restore strings --")
    for needle in STRING_NEEDLES:
        hits = all_hits(data, needle)
        key = needle.decode("ascii", "replace")
        result["strings"][key] = [
            {"offset": h, "va": f"0x{va(h):016x}", "region": region(h)} for h in hits
        ]
        print(f"{key!r}: {len(hits)} hit(s)")
        for h in hits[:64]:
            left = max(0, h - 32)
            right = min(len(data), h + len(needle) + 64)
            snippet = data[left:right]
            printable = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in snippet)
            print(f"  off=0x{h:08X} va=0x{va(h):016X} region={region(h)} :: {printable}")
        if len(hits) > 64:
            print(f"  ... {len(hits)-64} more")

    # Dump context only for exact request constants.  These snippets are often
    # enough to recognize mov/cmp immediates and the surrounding dispatch code.
    if all_ioctl_offsets:
        print("\n-- raw context around exact ioctl hits --")
        seen: set[int] = set()
        for h in sorted(all_ioctl_offsets):
            if h in seen:
                continue
            seen.add(h)
            print(f"\n### off=0x{h:08X} va=0x{va(h):016X} {region(h)}")
            print(hexdump(data, h, args.context, args.context))

    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nJSON written to: {args.json_path}")

    print("\nNext step: open the strongest text-region cluster in Ghidra as raw x86-64")
    print(f"image base 0x{TEXT_BASE:016X}; text length 0x{TEXT_SIZE:X}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
