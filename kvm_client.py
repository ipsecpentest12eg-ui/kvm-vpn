import argparse
import ctypes
from ctypes import wintypes
import json
import socket
import time
import sys

user32 = ctypes.windll.user32

# Fix Win32 API return types (ctypes default c_int truncates 8-byte returns on x64)
user32.SendInput.restype      = ctypes.c_uint   # UINT
user32.GetSystemMetrics.restype = ctypes.c_int  # int (explicit for clarity)

parser = argparse.ArgumentParser(description="KVM Client - receive input from server over TCP/VPN")
parser.add_argument("--host", required=True, help="Server IP (e.g. 10.14.x.x from Surfshark)")
parser.add_argument("--port", type=int, default=9876)
args = parser.parse_args()

# Cache screen dimensions at startup
_sw = user32.GetSystemMetrics(0)
_sh = user32.GetSystemMetrics(1)

# --- Win32 INPUT structs (correct ULONG_PTR as c_size_t) ---

INPUT_MOUSE    = 0
INPUT_KEYBOARD = 1

MOUSEEVENTF_MOVE      = 0x0001
MOUSEEVENTF_LEFTDOWN  = 0x0002
MOUSEEVENTF_LEFTUP    = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP   = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP  = 0x0040
MOUSEEVENTF_WHEEL     = 0x0800
MOUSEEVENTF_ABSOLUTE  = 0x8000

KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP       = 0x0002


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx",          ctypes.c_long),
        ("dy",          ctypes.c_long),
        ("mouseData",   wintypes.DWORD),
        ("dwFlags",     wintypes.DWORD),
        ("time",        wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),   # ULONG_PTR — 4 or 8 bytes depending on arch
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk",         wintypes.WORD),
        ("wScan",       wintypes.WORD),
        ("dwFlags",     wintypes.DWORD),
        ("time",        wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("_input", _INPUT_UNION)]


_INPUT_SIZE = ctypes.sizeof(INPUT)

# --- Input injection ---

def send_mouse_move(nx: float, ny: float):
    # nx/ny are normalized 0.0-1.0 from server; scale to absolute coords (0-65535)
    ax = max(0, min(65535, int(nx * 65535)))
    ay = max(0, min(65535, int(ny * 65535)))
    inp = INPUT()
    inp.type = INPUT_MOUSE
    inp._input.mi.dx = ax
    inp._input.mi.dy = ay
    inp._input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE
    user32.SendInput(1, ctypes.byref(inp), _INPUT_SIZE)


def send_mouse_button(btn: int, down: int):
    flag_map = {
        (1, 1): MOUSEEVENTF_LEFTDOWN,  (1, 0): MOUSEEVENTF_LEFTUP,
        (2, 1): MOUSEEVENTF_RIGHTDOWN, (2, 0): MOUSEEVENTF_RIGHTUP,
        (3, 1): MOUSEEVENTF_MIDDLEDOWN,(3, 0): MOUSEEVENTF_MIDDLEUP,
    }
    flag = flag_map.get((btn, down))
    if flag is None:
        return
    inp = INPUT()
    inp.type = INPUT_MOUSE
    inp._input.mi.dwFlags = flag
    user32.SendInput(1, ctypes.byref(inp), _INPUT_SIZE)


def send_scroll(raw_delta: int):
    # raw_delta is signed wheel delta (120 per click, positive = up)
    # mouseData high word must carry signed 16-bit delta
    high_word = ctypes.c_uint16(ctypes.c_int16(raw_delta).value).value
    inp = INPUT()
    inp.type = INPUT_MOUSE
    inp._input.mi.mouseData = ctypes.c_uint32(high_word << 16).value
    inp._input.mi.dwFlags = MOUSEEVENTF_WHEEL
    user32.SendInput(1, ctypes.byref(inp), _INPUT_SIZE)


def send_key(vk: int, sc: int, ext: bool, down: bool):
    flags = 0
    if not down:
        flags |= KEYEVENTF_KEYUP
    if ext:
        flags |= KEYEVENTF_EXTENDEDKEY
    inp = INPUT()
    inp.type = INPUT_KEYBOARD
    inp._input.ki.wVk = vk
    inp._input.ki.wScan = sc
    inp._input.ki.dwFlags = flags
    user32.SendInput(1, ctypes.byref(inp), _INPUT_SIZE)


def set_clipboard(text: str):
    try:
        import win32clipboard
        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(text, win32clipboard.CF_UNICODETEXT)
        finally:
            win32clipboard.CloseClipboard()
    except Exception:
        pass


def handle_event(evt: dict):
    t = evt.get("t")
    if t == "mm":
        send_mouse_move(evt["nx"], evt["ny"])
    elif t == "mk":
        send_mouse_button(evt["b"], evt["d"])
    elif t == "sc":
        send_scroll(evt.get("dy", 0))
    elif t == "ks":
        send_key(evt["vk"], evt.get("sc", 0), evt.get("ext", False), bool(evt["d"]))
    elif t == "clip":
        set_clipboard(evt.get("text", ""))


# --- TCP receive loop ---

_MAX_BUF = 65536  # guard against malformed/huge messages


def run():
    while True:
        s = None
        try:
            print(f"[CLIENT] Connecting to {args.host}:{args.port} ...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.settimeout(10)
            s.connect((args.host, args.port))
            s.settimeout(None)  # back to blocking after connect
            print(f"[CLIENT] Connected. Screen: {_sw}x{_sh}. Receiving input.")
            buf = ""
            while True:
                chunk = s.recv(4096).decode(errors="replace")
                if not chunk:
                    print("[CLIENT] Server closed connection.")
                    break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            handle_event(json.loads(line))
                        except (json.JSONDecodeError, KeyError):
                            pass
                # Drop incomplete residue only if it grew unreasonably large
                if len(buf) > _MAX_BUF:
                    print("[CLIENT] Warning: oversized incomplete message, discarding.")
                    buf = ""
        except KeyboardInterrupt:
            print("[CLIENT] Exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"[CLIENT] Error: {e} — retrying in 3s")
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        time.sleep(3)


run()
