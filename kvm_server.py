import argparse
import ctypes
from ctypes import wintypes
import json
import socket
import threading
import time
import sys

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

parser = argparse.ArgumentParser(description="KVM Server - share this PC's input over TCP/VPN")
parser.add_argument("--port", type=int, default=9876)
parser.add_argument("--switch-edge", choices=["right", "left"], default="right",
                    help="Screen edge that activates remote mode (default: right)")
parser.add_argument("--switch-threshold", type=int, default=5,
                    help="Pixels from edge to trigger switch (default: 5)")
args = parser.parse_args()

# --- Win32 hook structs ---

class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("pt", POINT),
        ("mouseData", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]

class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]

WH_MOUSE_LL    = 14
WH_KEYBOARD_LL = 13

WM_MOUSEMOVE   = 0x0200
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP   = 0x0202
WM_RBUTTONDOWN = 0x0204
WM_RBUTTONUP   = 0x0205
WM_MBUTTONDOWN = 0x0207
WM_MBUTTONUP   = 0x0208
WM_MOUSEWHEEL  = 0x020A
WM_KEYDOWN     = 0x0100
WM_KEYUP       = 0x0101
WM_SYSKEYDOWN  = 0x0104
WM_SYSKEYUP    = 0x0105
WM_QUIT        = 0x0012

LLMHF_INJECTED = 0x00000001  # event came from SendInput - skip to avoid re-capture loops

HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

# --- Shared state ---

_lock = threading.Lock()
_remote_mode = False
_conn_sock = None
_sw = user32.GetSystemMetrics(0)
_sh = user32.GetSystemMetrics(1)
_last_move_ns = 0
_MOVE_INTERVAL_NS = 16_000_000  # 60 Hz cap
_pump_tid = 0
_mouse_hook_fn = None  # keep HOOKPROC reference alive (ctypes GC issue)
_kb_hook_fn = None


def get_remote() -> bool:
    with _lock:
        return _remote_mode


def set_remote(val: bool, reason: str = ""):
    global _remote_mode
    with _lock:
        changed = _remote_mode != val
        _remote_mode = val
    if changed:
        label = "ON" if val else "OFF"
        print(f"[SERVER] Remote mode {label}{' — ' + reason if reason else ''}")
        if val:
            # Warp cursor to center so edge detection doesn't re-fire immediately
            user32.SetCursorPos(_sw // 2, _sh // 2)


def send_event(evt: dict):
    global _conn_sock
    with _lock:
        s = _conn_sock
    if s is None:
        return
    try:
        s.sendall((json.dumps(evt) + "\n").encode())
    except Exception:
        with _lock:
            _conn_sock = None
        set_remote(False, "client disconnected")

# --- Mouse low-level hook ---

def _mouse_proc(nCode: int, wParam: int, lParam: int) -> int:
    global _last_move_ns
    if nCode >= 0:
        info = ctypes.cast(lParam, ctypes.POINTER(MSLLHOOKSTRUCT)).contents
        if not (info.flags & LLMHF_INJECTED):
            rm = get_remote()
            x, y = info.pt.x, info.pt.y
            thr = args.switch_threshold

            if wParam == WM_MOUSEMOVE:
                if args.switch_edge == "right":
                    if not rm and x >= _sw - thr:
                        set_remote(True, "cursor at right edge")
                        return 1
                    elif rm and x <= thr:
                        set_remote(False, "cursor at left edge")
                        return 1
                else:
                    if not rm and x <= thr:
                        set_remote(True, "cursor at left edge")
                        return 1
                    elif rm and x >= _sw - thr:
                        set_remote(False, "cursor at right edge")
                        return 1

                if rm:
                    now = time.monotonic_ns()
                    if now - _last_move_ns >= _MOVE_INTERVAL_NS:
                        _last_move_ns = now
                        send_event({"t": "mm", "x": x, "y": y})
                    return 1  # suppress local event

            elif wParam in (WM_LBUTTONDOWN, WM_LBUTTONUP,
                            WM_RBUTTONDOWN, WM_RBUTTONUP,
                            WM_MBUTTONDOWN, WM_MBUTTONUP):
                if rm:
                    btn_map = {
                        WM_LBUTTONDOWN: (1, 1), WM_LBUTTONUP: (1, 0),
                        WM_RBUTTONDOWN: (2, 1), WM_RBUTTONUP: (2, 0),
                        WM_MBUTTONDOWN: (3, 1), WM_MBUTTONUP: (3, 0),
                    }
                    btn, down = btn_map[wParam]
                    send_event({"t": "mk", "b": btn, "d": down})
                    return 1

            elif wParam == WM_MOUSEWHEEL:
                if rm:
                    # High word of mouseData = signed wheel delta (120 per click)
                    raw_delta = ctypes.c_int16(info.mouseData >> 16).value
                    send_event({"t": "sc", "dy": raw_delta})
                    return 1

    return user32.CallNextHookEx(0, nCode, wParam, lParam)


# --- Keyboard low-level hook ---

def _kb_proc(nCode: int, wParam: int, lParam: int) -> int:
    if nCode >= 0:
        info = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
        if not (info.flags & LLMHF_INJECTED):
            if get_remote():
                down = wParam in (WM_KEYDOWN, WM_SYSKEYDOWN)
                send_event({
                    "t": "ks",
                    "vk": info.vkCode,
                    "sc": info.scanCode,
                    "ext": bool(info.flags & 0x01),
                    "d": 1 if down else 0,
                })
                return 1
    return user32.CallNextHookEx(0, nCode, wParam, lParam)


# --- Hook thread with message pump ---

def _hook_thread():
    global _pump_tid, _mouse_hook_fn, _kb_hook_fn

    _pump_tid = kernel32.GetCurrentThreadId()

    mfn = HOOKPROC(_mouse_proc)
    kfn = HOOKPROC(_kb_proc)
    _mouse_hook_fn = mfn  # prevent GC
    _kb_hook_fn = kfn

    mh = user32.SetWindowsHookExW(WH_MOUSE_LL, mfn, None, 0)
    kh = user32.SetWindowsHookExW(WH_KEYBOARD_LL, kfn, None, 0)

    if not mh or not kh:
        print("[SERVER] ERROR: Failed to install hooks. Try running as Administrator.")
        sys.exit(1)

    edge = args.switch_edge
    print(f"[SERVER] Hooks installed. Move cursor to {edge} edge to switch to client PC.")

    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))

    user32.UnhookWindowsHookEx(mh)
    user32.UnhookWindowsHookEx(kh)


# --- TCP accept loop ---

def _accept_loop(port: int):
    global _conn_sock
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"[SERVER] Listening on 0.0.0.0:{port}")
    while True:
        try:
            c, addr = srv.accept()
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            with _lock:
                old = _conn_sock
                _conn_sock = c
            if old:
                try:
                    old.close()
                except Exception:
                    pass
            print(f"[SERVER] Client connected from {addr[0]}")
        except Exception as e:
            print(f"[SERVER] Accept error: {e}")
            time.sleep(1)


# --- Entry point ---

threading.Thread(target=_accept_loop, args=(args.port,), daemon=True).start()

hook_t = threading.Thread(target=_hook_thread, daemon=True)
hook_t.start()

print(f"[SERVER] Running. Screen: {_sw}x{_sh}. Ctrl+C to exit.")
try:
    while hook_t.is_alive():
        time.sleep(0.5)
except KeyboardInterrupt:
    print("[SERVER] Exiting.")
    if _pump_tid:
        user32.PostThreadMessageW(_pump_tid, WM_QUIT, 0, 0)
    sys.exit(0)
