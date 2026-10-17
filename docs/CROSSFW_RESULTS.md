# Cross-firmware BAR research notes

These notes summarize read-only compatibility testing performed on a PS5 running system software 13.60.

## Samples

Two official PS5 Backup & Restore archives were compared:

- native archive created by the 13.60 console: BAR context version field 12
- newer archive: BAR context version field 13

No archive bytes were modified during the tests.

## Header authentication

Native v12 archive on FW 13.60:

- `BAR_CREATE_CONTEXT`: accepted
- `BAR_INIT_CONTEXT(version=12)`: accepted
- header/metadata/hash AAD updates: accepted
- `BAR_FINISH_DECRYPT`: accepted

Newer v13 archive on FW 13.60:

- `BAR_CREATE_CONTEXT`: accepted
- `BAR_INIT_CONTEXT(version=13)`: rejected with driver status low32 `-46`

Forcing only the context version to 12 allows init and AAD updates, but final header authentication fails. Changing an in-memory copy of the header version from 13 to 12 before AAD does not make the original v13 header tag validate.

## Segment decryption control

Segment 1 was used because native v12 plaintext is easy to recognize (`P5BR`). Multipart archive mapping was handled as a logical stream split at `0xFFFF0000` bytes per physical archive part.

On the native v12 archive:

- `BAR_INIT_CONTEXT(version=12)` succeeds
- `BAR_UPDATE_DECRYPT` produces valid segment-1 plaintext beginning with `P5BR`

On the v13 archive, forcing version 12:

- `BAR_INIT_CONTEXT(version=12)` succeeds
- `BAR_UPDATE_DECRYPT` returns success
- output is not valid segment-1 plaintext and does not begin with `P5BR`

Therefore v12 and v13 are not data-crypto compatible merely by changing the context version argument.

## Version sweep

The same v13 segment-1 ciphertext was tested with fresh `/dev/bar` contexts for versions 1 through 13 on FW 13.60.

- versions 1..12: context init and decrypt calls are accepted, but none produce `P5BR`
- version 13: context init is rejected with status low32 `-46`

This rules out a simple alias to an older accepted protocol version on FW 13.60.

## Important caveat about segment tags

Calling `BAR_FINISH_DECRYPT` with the segment-table 16-byte value returns low32 `-36` even for the native v12 archive whose decrypted plaintext is demonstrably correct. The upstream segment-decrypt path does not use `BAR_FINISH_DECRYPT` after each segment either. Therefore that value/result must not currently be treated as a valid per-segment authentication oracle.

## BAR device/module inventory probe

A read-only probe opened `/dev/bar` and called `fstat()` successfully:

- `st_ino = 0x56`
- `st_rdev = 0x56`
- `st_mode = 0x2180`

The same probe attempted FreeBSD `kldnext`/`kldstat` and `modnext`/`modstat` enumeration. All of those raw syscall stubs returned decimal `78` with libc `errno` still zero. In the PS5 SDK's FreeBSD errno table, `78` is `ENOSYS` (`Function not implemented`). Because the SDK syscall stubs return the raw kernel value directly, the first version of the probe incorrectly treated `78` as a KLD/module identifier and repeated it until its safety loop limits (512 and 2048 iterations).

Therefore there is no evidence for a real KLD or module with ID 78. The useful conclusion is instead that the standard KLD/module enumeration syscalls are unavailable from this payload context on FW 13.60.

The next offline approach is to use the captured kernel data layout plus the FreeBSD `struct cdev` / `struct cdevsw` layout to look for the in-memory `/dev/bar` device object and its `d_ioctl` handler pointer. `tools/scan_bar_cdev.py` implements this as a read-only scan of the existing kernel RAM reconstruction.

## Current conclusion

FW 13.60 can parse and decrypt its native BAR v12 data but does not have a directly usable v13 context through the tested `/dev/bar` API. A v13 archive cannot be recovered by merely substituting any older context version 1..12. Standard KLD/module enumeration is also unavailable (`ENOSYS`) in the tested payload context, so implementation research is moving to offline identification of `/dev/bar`'s `cdevsw` and `d_ioctl` path in the existing 13.60 kernel RAM capture.
