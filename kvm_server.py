import argparse
import ctypes
from ctypes import wintypes
import json
import queue as _queue
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

LLMHF_INJECTED = 0x00000001

# VK codes that are always handled locally even in remote mode
VK_SCROLL = 0x91  # ScrollLock — toggle remote mode off
VK_PAUSE  = 0x13  # Pause/Break — emergency local exit

# Fix Win32 API return types before any call.
# Default ctypes restype is c_int (4 bytes); on 64-bit Windows several APIs return
# 8-byte values and truncation corrupts them.
user32.SetWindowsHookExW.restype  = ctypes.c_void_p   # HHOOK = pointer (8B on x64)
user32.CallNextHookEx.restype     = wintypes.LPARAM    # LRESULT = LONG_PTR (8B on x64)
user32.GetAsyncKeyState.restype   = ctypes.c_short     # SHORT (2B, signed)
user32.UnhookWindowsHookEx.restype = ctypes.c_int      # BOOL (4B, explicit for clarity)
kernel32.GetCurrentThreadId.restype = wintypes.DWORD   # DWORD (4B, explicit)

# HOOKPROC: return type must be LRESULT (LONG_PTR = 8B on x64), not c_long (4B).
# lParam is LPARAM (LONG_PTR) used as a pointer to hook data — c_void_p is correct.
HOOKPROC = ctypes.WINFUNCTYPE(wintypes.LPARAM, ctypes.c_int, wintypes.WPARAM, ctypes.c_void_p)

# --- Shared state ---

_lock = threading.Lock()
_remote_mode = False
_conn_sock = None
_sw = user32.GetSystemMetrics(0)
_sh = user32.GetSystemMetrics(1)
_last_move_ns = 0
_MOVE_INTERVAL_NS = 16_000_000  # 60 Hz cap
_pump_tid = 0
_mouse_hook_fn = None
_kb_hook_fn = None
# Suppresses the SetCursorPos warp event that would otherwise be forwarded to the client
_warping = False

_send_q: _queue.Queue = _queue.Queue(maxsize=1024)
_exit_event = threading.Event()


def get_remote() -> bool:
    with _lock:
        return _remote_mode


def set_remote(val: bool, reason: str = ""):
    global _remote_mode, _warping
    with _lock:
        changed = _remote_mode != val
        _remote_mode = val
    if changed:
        label = "ON" if val else "OFF"
        print(f"[SERVER] Remote mode {label}{' — ' + reason if reason else ''}")
        if val:
            # Warp cursor to center so edge detection doesn't re-fire immediately.
            # _warping suppresses the resulting WM_MOUSEMOVE from reaching the client.
            _warping = True
            user32.SetCursorPos(_sw // 2, _sh // 2)
            _warping = False


def send_event(evt: dict):
    # FIX 1: non-blocking put; drop event if queue is full (heavy backpressure)
    try:
        _send_q.put_nowait(evt)
    except _queue.Full:
        pass


def _sender_thread():
    global _conn_sock
    while not _exit_event.is_set():
        try:
            evt = _send_q.get(timeout=0.2)
        except _queue.Empty:
            continue
        with _lock:
            s = _conn_sock
        if s is None:
            continue
        try:
            s.sendall((json.dumps(evt) + "\n").encode())
        except Exception:
            with _lock:
                # Only clear if the socket hasn't been replaced by a new connection
                if _conn_sock is s:
                    _conn_sock = None
            set_remote(False, "client disconnected")


# --- Mouse low-level hook ---

def _mouse_proc(nCode: int, wParam: int, lParam: int) -> int:
    global _last_move_ns
    if nCode >= 0:
        if _warping:
            return user32.CallNextHookEx(0, nCode, wParam, lParam)
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
                        # Send normalized 0.0-1.0 coords so client scales to its own resolution
                        send_event({"t": "mm",
                                    "nx": x / _sw if _sw > 0 else 0.0,
                                    "ny": y / _sh if _sh > 0 else 0.0})
                    return 1

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
                    raw_delta = ctypes.c_int16(info.mouseData >> 16).value
                    send_event({"t": "sc", "dy": raw_delta})
                    return 1

    return user32.CallNextHookEx(0, nCode, wParam, lParam)


# --- Keyboard low-level hook ---

def _kb_proc(nCode: int, wParam: int, lParam: int) -> int:
    if nCode >= 0:
        info = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
        if not (info.flags & LLMHF_INJECTED):
            vk = info.vkCode
            down = wParam in (WM_KEYDOWN, WM_SYSKEYDOWN)

            # FIX 2: emergency local keys — always processed locally, never forwarded.
            # ScrollLock  → exit remote mode (keeps working as normal ScrollLock key)
            # Pause/Break → emergency hard exit of the script
            if vk == VK_SCROLL and down:
                if get_remote():
                    set_remote(False, "ScrollLock pressed")
                return user32.CallNextHookEx(0, nCode, wParam, lParam)

            if vk == VK_PAUSE and down:
                print("[SERVER] Pause/Break pressed — force exit.")
                _exit_event.set()
                if _pump_tid:
                    user32.PostThreadMessageW(_pump_tid, WM_QUIT, 0, 0)
                sys.exit(0)

            # FIX 3: let Ctrl+C reach Python even in remote mode so KeyboardInterrupt works
            # Ctrl = VK_CONTROL (0x11) or VK_LCONTROL (0xA2) / VK_RCONTROL (0xA3)
            if vk == 0x43 and down:  # 'C' key
                ctrl_held = (user32.GetAsyncKeyState(0x11) & 0x8000) != 0
                if ctrl_held:
                    # Let it through — Python's Ctrl+C handler will catch it
                    return user32.CallNextHookEx(0, nCode, wParam, lParam)

            if get_remote():
                send_event({
                    "t": "ks",
                    "vk": vk,
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
    _mouse_hook_fn = mfn
    _kb_hook_fn = kfn

    mh = user32.SetWindowsHookExW(WH_MOUSE_LL, mfn, None, 0)
    kh = user32.SetWindowsHookExW(WH_KEYBOARD_LL, kfn, None, 0)

    if not mh or not kh:
        print("[SERVER] ERROR: Failed to install hooks. Try running as Administrator.")
        sys.exit(1)

    edge = args.switch_edge
    print(f"[SERVER] Hooks installed. Move cursor to {edge} edge to switch to client PC.")
    print(f"[SERVER] Emergency exit: ScrollLock exits remote mode | Pause/Break force-quits")

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

threading.Thread(target=_sender_thread, daemon=True).start()
threading.Thread(target=_accept_loop, args=(args.port,), daemon=True).start()

hook_t = threading.Thread(target=_hook_thread, daemon=True)
hook_t.start()

print(f"[SERVER] Running. Screen: {_sw}x{_sh}. Ctrl+C to exit.")
try:
    while hook_t.is_alive():
        time.sleep(0.5)
except KeyboardInterrupt:
    print("[SERVER] Exiting.")
    _exit_event.set()
    if _pump_tid:
        user32.PostThreadMessageW(_pump_tid, WM_QUIT, 0, 0)
    sys.exit(0)
