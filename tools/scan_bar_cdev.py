#!/usr/bin/env python3
import argparse
import json
import struct
from pathlib import Path

DEFAULT_TEXT_BASE = 0xFFFFFFFF9E3F0000
DEFAULT_TEXT_SIZE = 0xCC0000
DEFAULT_DATA_BASE = 0xFFFFFFFF9F0B0000

# FreeBSD 11.4 amd64 layout from sys/conf.h in ps5-payload-dev SDK.
CDEV_SIZE = 0x120
CDEV_SI_DEVSW_OFF = 0xB8
CDEV_SI_NAME_OFF = 0xE0
CDEVSW_SIZE = 0xB8
CDEVSW_D_NAME_OFF = 0x08
CDEVSW_D_IOCTL_OFF = 0x38
D_VERSION_03 = 0x17122009


def u32(buf, off):
    if off < 0 or off + 4 > len(buf):
        return None
    return struct.unpack_from('<I', buf, off)[0]


def u64(buf, off):
    if off < 0 or off + 8 > len(buf):
        return None
    return struct.unpack_from('<Q', buf, off)[0]


def read_cstr(buf, off, limit=128):
    if off is None or off < 0 or off >= len(buf):
        return None
    end = buf.find(b'\0', off, min(len(buf), off + limit))
    if end < 0:
        end = min(len(buf), off + limit)
    raw = buf[off:end]
    try:
        return raw.decode('ascii')
    except UnicodeDecodeError:
        return raw.decode('ascii', errors='replace')


def find_all(buf, needle):
    start = 0
    while True:
        off = buf.find(needle, start)
        if off < 0:
            return
        yield off
        start = off + 1


def make_mapper(file_size, text_base, text_size, data_base):
    data_file_off = text_size
    data_size = max(0, file_size - data_file_off)

    def off_to_va(off):
        if 0 <= off < text_size:
            return text_base + off
        if data_file_off <= off < file_size:
            return data_base + (off - data_file_off)
        return None

    def va_to_off(va):
        if text_base <= va < text_base + text_size:
            return va - text_base
        if data_base <= va < data_base + data_size:
            return data_file_off + (va - data_base)
        return None

    def region_for_va(va):
        if text_base <= va < text_base + text_size:
            return 'text'
        if data_base <= va < data_base + data_size:
            return 'data'
        return 'outside_capture'

    return off_to_va, va_to_off, region_for_va


def scan(kernel_path, text_base, text_size, data_base):
    data = Path(kernel_path).read_bytes()
    off_to_va, va_to_off, region_for_va = make_mapper(len(data), text_base, text_size, data_base)

    result = {
        'file': str(kernel_path),
        'size': len(data),
        'layout': {
            'text_base': hex(text_base),
            'text_size': hex(text_size),
            'data_base': hex(data_base),
            'cdev_size': hex(CDEV_SIZE),
            'cdev_si_devsw_off': hex(CDEV_SI_DEVSW_OFF),
            'cdev_si_name_off': hex(CDEV_SI_NAME_OFF),
            'cdevsw_size': hex(CDEVSW_SIZE),
            'cdevsw_d_name_off': hex(CDEVSW_D_NAME_OFF),
            'cdevsw_d_ioctl_off': hex(CDEVSW_D_IOCTL_OFF),
        },
        'bar_string_hits': [],
        'inline_cdev_candidates': [],
        'cdevsw_name_pointer_candidates': [],
    }

    bar_hits = list(find_all(data, b'bar\0'))
    for hit in bar_hits:
        result['bar_string_hits'].append({
            'file_offset': hex(hit),
            'va': hex(off_to_va(hit)) if off_to_va(hit) is not None else None,
        })

        # Candidate 1: struct cdev has si_name inline at +0xE0.
        base = hit - CDEV_SI_NAME_OFF
        if base >= 0 and base + CDEV_SIZE <= len(data):
            devsw_va = u64(data, base + CDEV_SI_DEVSW_OFF)
            devsw_off = va_to_off(devsw_va) if devsw_va is not None else None
            cand = {
                'cdev_file_offset': hex(base),
                'cdev_va': hex(off_to_va(base)) if off_to_va(base) is not None else None,
                'si_name': read_cstr(data, hit, 64),
                'si_devsw_va': hex(devsw_va) if devsw_va is not None else None,
                'si_devsw_region': region_for_va(devsw_va) if devsw_va is not None else None,
            }
            if devsw_off is not None and devsw_off + CDEVSW_SIZE <= len(data):
                d_version = u32(data, devsw_off)
                d_name_va = u64(data, devsw_off + CDEVSW_D_NAME_OFF)
                d_ioctl_va = u64(data, devsw_off + CDEVSW_D_IOCTL_OFF)
                d_name_off = va_to_off(d_name_va) if d_name_va is not None else None
                cand.update({
                    'cdevsw_file_offset': hex(devsw_off),
                    'd_version': hex(d_version) if d_version is not None else None,
                    'd_version_matches_freebsd_11_4': d_version == D_VERSION_03,
                    'd_name_va': hex(d_name_va) if d_name_va is not None else None,
                    'd_name': read_cstr(data, d_name_off, 128) if d_name_off is not None else None,
                    'd_ioctl_va': hex(d_ioctl_va) if d_ioctl_va is not None else None,
                    'd_ioctl_region': region_for_va(d_ioctl_va) if d_ioctl_va is not None else None,
                    'd_ioctl_file_offset': hex(va_to_off(d_ioctl_va)) if d_ioctl_va is not None and va_to_off(d_ioctl_va) is not None else None,
                })
            result['inline_cdev_candidates'].append(cand)

        # Candidate 2: standalone string referenced by cdevsw.d_name.
        hit_va = off_to_va(hit)
        if hit_va is not None:
            ptr = struct.pack('<Q', hit_va)
            for ptr_hit in find_all(data, ptr):
                devsw_base = ptr_hit - CDEVSW_D_NAME_OFF
                if devsw_base < 0 or devsw_base + CDEVSW_SIZE > len(data):
                    continue
                d_version = u32(data, devsw_base)
                d_ioctl_va = u64(data, devsw_base + CDEVSW_D_IOCTL_OFF)
                result['cdevsw_name_pointer_candidates'].append({
                    'bar_string_va': hex(hit_va),
                    'd_name_pointer_file_offset': hex(ptr_hit),
                    'cdevsw_file_offset': hex(devsw_base),
                    'cdevsw_va': hex(off_to_va(devsw_base)) if off_to_va(devsw_base) is not None else None,
                    'd_version': hex(d_version) if d_version is not None else None,
                    'd_version_matches_freebsd_11_4': d_version == D_VERSION_03,
                    'd_ioctl_va': hex(d_ioctl_va) if d_ioctl_va is not None else None,
                    'd_ioctl_region': region_for_va(d_ioctl_va) if d_ioctl_va is not None else None,
                    'd_ioctl_file_offset': hex(va_to_off(d_ioctl_va)) if d_ioctl_va is not None and va_to_off(d_ioctl_va) is not None else None,
                })

    return result


def print_summary(result):
    print('=== /dev/bar cdev/cdevsw offline scan ===')
    print(f"file={result['file']}")
    print(f"size=0x{result['size']:X}")
    print(f"bar\\0 hits={len(result['bar_string_hits'])}")
    print(f"inline cdev candidates={len(result['inline_cdev_candidates'])}")
    print(f"cdevsw d_name pointer candidates={len(result['cdevsw_name_pointer_candidates'])}")
    print()

    for i, cand in enumerate(result['inline_cdev_candidates']):
        print(f"[inline-cdev {i}] cdev_va={cand.get('cdev_va')} si_devsw={cand.get('si_devsw_va')} ({cand.get('si_devsw_region')})")
        if 'd_version' in cand:
            print(f"  d_version={cand.get('d_version')} match={cand.get('d_version_matches_freebsd_11_4')}")
            print(f"  d_name={cand.get('d_name')!r} d_name_va={cand.get('d_name_va')}")
            print(f"  d_ioctl={cand.get('d_ioctl_va')} ({cand.get('d_ioctl_region')}) file_off={cand.get('d_ioctl_file_offset')}")

    for i, cand in enumerate(result['cdevsw_name_pointer_candidates']):
        print(f"[cdevsw-nameptr {i}] cdevsw_va={cand.get('cdevsw_va')} d_version={cand.get('d_version')} match={cand.get('d_version_matches_freebsd_11_4')}")
        print(f"  d_ioctl={cand.get('d_ioctl_va')} ({cand.get('d_ioctl_region')}) file_off={cand.get('d_ioctl_file_offset')}")


def main():
    ap = argparse.ArgumentParser(description='Locate likely /dev/bar struct cdev / cdevsw objects in a flat PS5 kernel RAM reconstruction.')
    ap.add_argument('kernel', type=Path)
    ap.add_argument('--text-base', type=lambda x: int(x, 0), default=DEFAULT_TEXT_BASE)
    ap.add_argument('--text-size', type=lambda x: int(x, 0), default=DEFAULT_TEXT_SIZE)
    ap.add_argument('--data-base', type=lambda x: int(x, 0), default=DEFAULT_DATA_BASE)
    ap.add_argument('--json-out', type=Path)
    args = ap.parse_args()

    result = scan(args.kernel, args.text_base, args.text_size, args.data_base)
    print_summary(result)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(f"\nJSON written to: {args.json_out}")


if __name__ == '__main__':
    main()
