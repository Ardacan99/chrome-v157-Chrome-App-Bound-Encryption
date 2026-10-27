# IElevator Vtable Reconstruction

## Source

Reconstructed via:
- `elevation_service.exe` disassembly (Ghidra / IDA)
- `chrome.dll` COM stub analysis
- Windows COMTrace / OleViewDotNet

## Chrome Beta vtable

CLSID `{DD2646BA-3707-4BF8-B9A7-038691A68FC2}`  
IID   `{B96A14B8-D0B0-44D8-BA68-2385B2A03254}`

```
Index  Method                Signature (IDL-style)
-----  --------------------  --------------------------------------------------
0      QueryInterface        HRESULT(REFIID, void**)
1      AddRef                ULONG()
2      Release               ULONG()
3      RunRecoveryAction     HRESULT(LPCWSTR action, BSTR* result, DWORD* err)
4      EncryptData           HRESULT(BSTR plaintext, BSTR* encrypted, DWORD* err)
5      DecryptData           HRESULT(BSTR encrypted, BSTR* plaintext, DWORD* err)
```

## Notes on BSTR convention

Chrome's IElevator uses **byte-length BSTR** (not character-length):

```c
// Allocate: pass raw bytes, not a null-terminated wide string
BSTR bstr_in = SysAllocStringByteLen((LPCSTR)key_blob, (UINT)key_blob_size);

// After DecryptData:
UINT byte_len = SysStringByteLen(bstr_out);   // byte count
// read key_blob_size bytes from bstr_out
```

Using `SysAllocString` (character-length) corrupts the blob.

## Access denied analysis

`DecryptData` fails with `hr=0x8004A003` when any of these checks fail:

| Check | Details |
|-------|---------|
| Caller binary signature | Must be Google-signed `chrome.exe` |
| Caller path | Must match the registered Chrome Beta install path |
| Process integrity | Medium or High integrity required |
| Key blob origin | Must have been produced by `EncryptData` on the same machine |

The flag `--elevator-allow-untrusted-path-for-testing` relaxes only the path
check; the signature check remains active on production builds.

## Chrome stable vtable (for reference)

CLSID `{708860E0-F641-4611-8895-7D867DD3675B}`  
IID   `{463ABECF-410D-407F-8AF5-0DF35A005CC8}`

vtable layout identical; only IDs differ.
