# Chrome ABE Key Blob — Byte-Level Analysis

## Flag=3 Full Layout (93 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     flag = 0x03
1       32    encrypted_aes_key
              └─ NCryptDecrypt("Google Chromekey1") gives 32 raw bytes
              └─ those 32 bytes XORed with build-specific seed
              └─ result = intermediate_key used for AES-GCM below
33      12    iv / nonce
45      32    ciphertext  (AES-GCM encrypted master key)
77      16    GCM authentication tag
```

**Derivation chain:**

```
NCryptDecrypt(
    key_name = "Google Chromekey1",
    data     = encrypted_aes_key[1:33]
) = raw_key_material (32 bytes)

intermediate = raw_key_material XOR xor_seed   # seed = hardcoded per build

master_key = AES_GCM_decrypt(
    key   = intermediate,
    nonce = blob[33:45],
    ct    = blob[45:77],
    tag   = blob[77:93]
)  # 32 bytes
```

The XOR seed can be extracted from `chrome.dll` / `chrome_child.dll` by:
1. Finding `BCryptDecrypt` call site for the intermediate key
2. Reading the 32-byte array passed as the second operand to the XOR instruction

---

## Flag=4 Full Layout (138 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     flag = 0x04
1       137   opaque_blob
              ├─ 4 bytes  version/magic
              ├─ 32 bytes wrapped key material (machine-bound)
              ├─ 12 bytes nonce
              ├─ 64 bytes encrypted payload
              └─ 25 bytes metadata / MAC
```

The exact internal structure is not publicly documented. The elevation service
reconstructs the master key from:
- A per-machine LSA secret (`L$CHROME_ELEVATION_SERVICE_KEY` or similar)
- TPM-backed key on supported hardware
- Caller identity check (signed Chrome binary, matching install path)

---

## v20 Password Blob Layout

```
Offset  Size  Field
------  ----  -----
0       3     b"v20"  magic
3       12    nonce   (random per-entry AES-GCM nonce)
15      N     ciphertext  (N = len(plaintext))
15+N    16    GCM tag
```

Total: 3 + 12 + N + 16 = N + 31 bytes.

Chrome generates a fresh nonce for each password entry. All entries under one
profile use the same 32-byte master key.
