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

## Current conclusion

FW 13.60 can parse and decrypt its native BAR v12 data but does not have a directly usable v13 context through the tested `/dev/bar` API. A v13 archive cannot be recovered by merely substituting any older context version 1..12. Further work should focus on the implementation/derivation difference for BAR context version 13 or on executing the BAR API on a firmware that natively supports v13.
