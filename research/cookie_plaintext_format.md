# Cookie Plaintext Format — Chrome 127+

## 32-byte domain binding prefix

After AES-GCM decryption of a cookie `encrypted_value`, the plaintext is **not** the raw
cookie value. Chrome prepends a 32-byte per-domain binding context before encrypting:

```
decrypted_plaintext = [32 bytes domain context] + [actual cookie value]
```

The 32 bytes are deterministic per eTLD+1: all cookies from the same domain share the
same prefix; cookies from different domains have different prefixes.

Observed on Chrome Beta 157 (flag=4, master key recovered via memory scan):

| Domain             | Prefix (hex)                                               |
|--------------------|------------------------------------------------------------|
| `.google.com`      | `5d59719991ce1e2237eef373ad1cc97eafbd4d9738f18d37d86e7816e1b4f6dc` |
| `.youtube.com`     | `3cb2615ea92898b6af65d28395212b7afbc91b2afd060e8163d1284f836aef49` |
| `.google.com.tr`   | `60f00ac8968400cf7597d46db00a47b017bddce21699a4bfe670cfa6a050b50d` |
| `.doubleclick.net` | `3bf859e5fb334ef973ef85423d882109ebfe313f9ade252ef8263d3edfb51bb4` |

## Recovering the cookie value

```python
from Crypto.Cipher import AES

COOKIE_PREFIX_LEN = 32

def decrypt_cookie(master_key: bytes, blob: bytes) -> str:
    # blob = b"v20" + nonce(12) + ciphertext + tag(16)
    nonce = blob[3:15]
    ct    = blob[15:-16]
    tag   = blob[-16:]
    pt    = AES.new(master_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    return pt[COOKIE_PREFIX_LEN:].decode("utf-8", errors="replace")
```

## Passwords vs cookies

| Data type | Strip bytes | Reason                                      |
|-----------|-------------|---------------------------------------------|
| Password  | 0           | Plaintext is the raw password string        |
| Cookie    | 32          | Chrome prepends 32-byte domain binding      |

The GCM tag still verifies correctly with `strip=0` — the prefix is part of the
authenticated plaintext, not an outer wrapper. Stripping happens **after** `decrypt_and_verify`.

## Blob format recap

```
encrypted_value (cookies DB column):

offset  size  field
------  ----  -----
0       3     magic "v20"
3       12    AES-GCM nonce
15      N     ciphertext  (N = plaintext_len = 32 + cookie_value_len)
15+N    16    GCM authentication tag
```
