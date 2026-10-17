#!/usr/bin/env python3
import argparse
import json
import struct
from pathlib import Path

DEFAULT_TEXT_BASE = 0xFFFFFFFF9E3F0000
DEFAULT_TEXT_SIZE = 0xCC0000
DEFAULT_DATA_BASE = 0xFFFFFFFF9F0B0000


def parse_int(v):
    if isinstance(v, int):
        return v
    return int(v, 0)


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

    def region(va):
        if text_base <= va < text_base + text_size:
            return 'text'
        if data_base <= va < data_base + data_size:
            return 'data'
        return 'outside_capture'

    return off_to_va, va_to_off, region


def choose_candidate(scan):
    cands = scan.get('cdevsw_name_pointer_candidates', [])
    preferred = [c for c in cands if c.get('d_version_matches_freebsd_11_4') and c.get('d_ioctl_region') == 'text']
    if len(preferred) == 1:
        return preferred[0]
    if not preferred:
        raise SystemExit('No unique text-region cdevsw candidate with matching d_version was found.')
    raise SystemExit(f'Ambiguous: found {len(preferred)} matching text-region candidates.')


def main():
    ap = argparse.ArgumentParser(description='Resolve the first x86-64 rel32 JMP behind the BAR cdevsw d_ioctl pointer and extract the real handler bytes.')
    ap.add_argument('kernel', type=Path)
    ap.add_argument('cdev_scan_json', type=Path)
    ap.add_argument('--out-bin', type=Path, required=True)
    ap.add_argument('--out-json', type=Path)
    ap.add_argument('--extract-size', type=lambda x: int(x, 0), default=0x6000)
    args = ap.parse_args()

    kernel = args.kernel.read_bytes()
    scan = json.loads(args.cdev_scan_json.read_text(encoding='utf-8'))

    layout = scan.get('layout', {})
    text_base = parse_int(layout.get('text_base', DEFAULT_TEXT_BASE))
    text_size = parse_int(layout.get('text_size', DEFAULT_TEXT_SIZE))
    data_base = parse_int(layout.get('data_base', DEFAULT_DATA_BASE))
    off_to_va, va_to_off, region = make_mapper(len(kernel), text_base, text_size, data_base)

    cand = choose_candidate(scan)
    thunk_va = parse_int(cand['d_ioctl_va'])
    thunk_off = va_to_off(thunk_va)
    if thunk_off is None or thunk_off + 5 > len(kernel):
        raise SystemExit('d_ioctl thunk is outside the captured kernel image.')

    op = kernel[thunk_off]
    if op != 0xE9:
        raise SystemExit(f'Expected rel32 JMP (E9) at d_ioctl thunk, found opcode 0x{op:02X}.')

    rel = struct.unpack_from('<i', kernel, thunk_off + 1)[0]
    handler_va = (thunk_va + 5 + rel) & 0xFFFFFFFFFFFFFFFF
    handler_off = va_to_off(handler_va)
    if handler_off is None:
        raise SystemExit(f'Resolved handler {handler_va:#x} is outside the capture.')

    size = min(args.extract_size, len(kernel) - handler_off)
    blob = kernel[handler_off:handler_off + size]
    args.out_bin.parent.mkdir(parents=True, exist_ok=True)
    args.out_bin.write_bytes(blob)

    result = {
        'kernel': str(args.kernel),
        'd_ioctl_thunk_va': hex(thunk_va),
        'd_ioctl_thunk_file_offset': hex(thunk_off),
        'thunk_opcode': 'E9 rel32',
        'rel32': rel,
        'handler_va': hex(handler_va),
        'handler_file_offset': hex(handler_off),
        'handler_region': region(handler_va),
        'extracted_size': hex(size),
        'out_bin': str(args.out_bin),
    }

    print('=== BAR d_ioctl thunk resolver ===')
    print(f'd_ioctl thunk : {thunk_va:#018x}  file_off={thunk_off:#x}')
    print(f'jmp rel32     : {rel:+#x}')
    print(f'real handler  : {handler_va:#018x}  file_off={handler_off:#x}  region={region(handler_va)}')
    print(f'extracted     : {size:#x} bytes -> {args.out_bin}')

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(f'json          : {args.out_json}')


if __name__ == '__main__':
    main()
