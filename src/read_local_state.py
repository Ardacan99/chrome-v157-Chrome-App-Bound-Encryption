"""
Parse Chrome Local State — extract and inspect the ABE key blob.
"""
import base64
import json
import os


def ardacan_read_blob(browser: str = "Chrome Beta") -> tuple[int, bytes]:
    """
    Read the app_bound_encrypted_key from Local State.
    Returns (flag, raw_blob_after_flag).

    flag values:
        1  = DPAPI only (pre-127)
        2  = DPAPI + IElevator v1 (127-129)
        3  = CNG NCrypt + XOR + AES-GCM (130-156)
        4  = IElevator v2 opaque (157+)
    """
    paths = {
        "Chrome Beta":  r"Google\Chrome Beta\User Data\Local State",
        "Chrome":       r"Google\Chrome\User Data\Local State",
        "Edge":         r"Microsoft\Edge\User Data\Local State",
    }
    lad  = os.environ.get("LOCALAPPDATA", "")
    path = os.path.join(lad, paths.get(browser, paths["Chrome Beta"]))

    with open(path, "r", encoding="utf-8") as f:
        ls = json.load(f)

    raw_b64 = ls["os_crypt"]["app_bound_encrypted_key"]
    raw     = base64.b64decode(raw_b64)

    # Strip 4-byte prefix ("APPB" or version header)
    blob = raw[4:]
    flag = blob[0]
    return flag, blob[1:]


def ardacan_describe(browser: str = "Chrome Beta") -> None:
    flag, payload = ardacan_read_blob(browser)

    print(f"Browser  : {browser}")
    print(f"Flag     : {flag} (0x{flag:02x})")
    print(f"Payload  : {len(payload)} bytes")
    print(f"Payload  : {payload.hex()[:64]}...")

    descriptions = {
        1: "DPAPI-only (pre-Chrome 127) — use CryptUnprotectData directly",
        2: "DPAPI + IElevator v1 (Chrome 127-129) — strip DPAPI wrapper then call DecryptData",
        3: "CNG NCrypt + XOR + AES-GCM (Chrome 130-156) — NCryptDecrypt('Google Chromekey1') → XOR → AES-GCM",
        4: "IElevator v2 opaque (Chrome 157+) — only elevation service can decrypt; use memory scan as fallback",
    }
    print(f"Meaning  : {descriptions.get(flag, 'unknown flag')}")

    if flag == 3:
        print("\nFlag=3 layout:")
        print(f"  encrypted_aes_key : {payload[:32].hex()}")
        print(f"  iv (nonce)        : {payload[32:44].hex()}")
        print(f"  ciphertext        : {payload[44:76].hex()}")
        print(f"  GCM tag           : {payload[76:92].hex()}")

    if flag == 4:
        print("\nFlag=4: opaque blob — use src/memory_scan.py to recover master key")


if __name__ == "__main__":
    import sys
    browser = sys.argv[1] if len(sys.argv) > 1 else "Chrome Beta"
    ardacan_describe(browser)
