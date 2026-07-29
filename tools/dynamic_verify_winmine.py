import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXE = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "winmine.exe"
OUT_DIR = ROOT / "analysis"
EXPECTED_SHA256 = "D1A612A1791614B628A5C99F03B60FF1B979B8D1F088E99228893CB000C5DAF4"

ADDR_GAME_FLAGS = 0x01005000
ADDR_FACE_STATE = 0x01005160
ADDR_WIDTH = 0x01005334
ADDR_HEIGHT = 0x01005338
ADDR_MINE_COUNT_CURRENT = 0x01005330
ADDR_BOARD = 0x01005340
ADDR_OPENED = 0x010057A4
ADDR_SAFE_TOTAL = 0x010057A0
ADDR_TIMER = 0x0100579C

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
WM_CLOSE = 0x0010
MK_LBUTTON = 0x0001

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

user32.EnumWindows.argtypes = [EnumWindowsProc, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.SendMessageW.restype = wintypes.LPARAM
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.PostMessageW.restype = wintypes.BOOL
user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.SetForegroundWindow.restype = wintypes.BOOL
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetWindowRect.restype = wintypes.BOOL
user32.GetWindowDC.argtypes = [wintypes.HWND]
user32.GetWindowDC.restype = wintypes.HDC
user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
user32.ReleaseDC.restype = ctypes.c_int
user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
user32.PrintWindow.restype = wintypes.BOOL

gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
gdi32.CreateCompatibleDC.restype = wintypes.HDC
gdi32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
gdi32.SelectObject.restype = wintypes.HGDIOBJ
gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
gdi32.DeleteObject.restype = wintypes.BOOL
gdi32.DeleteDC.argtypes = [wintypes.HDC]
gdi32.DeleteDC.restype = wintypes.BOOL
gdi32.GetDIBits.argtypes = [
    wintypes.HDC,
    wintypes.HBITMAP,
    wintypes.UINT,
    wintypes.UINT,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.UINT,
]
gdi32.GetDIBits.restype = ctypes.c_int


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", wintypes.DWORD * 3),
    ]

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def get_window_title(hwnd):
    length = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, len(buf))
    return buf.value


def find_main_window(pid, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        matches = []

        @EnumWindowsProc
        def enum_proc(hwnd, lparam):
            window_pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
            if window_pid.value == pid and user32.IsWindowVisible(hwnd):
                matches.append((hwnd, get_window_title(hwnd)))
            return True

        user32.EnumWindows(enum_proc, 0)
        if matches:
            return matches[0]
        time.sleep(0.1)
    return None, ""


def open_process(pid):
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    return handle


def read_bytes(handle, addr, size):
    buf = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(addr),
        buf,
        size,
        ctypes.byref(read),
    )
    if not ok or read.value != size:
        raise OSError(ctypes.get_last_error(), "ReadProcessMemory failed at 0x%08X" % addr)
    return bytes(buf)


def read_dword(handle, addr):
    return int.from_bytes(read_bytes(handle, addr, 4), "little", signed=True)


def read_state(handle):
    width = read_dword(handle, ADDR_WIDTH)
    height = read_dword(handle, ADDR_HEIGHT)
    board = read_bytes(handle, ADDR_BOARD, 0x360)
    cells = []
    mines = []
    safe = []
    for row in range(1, height + 1):
        for col in range(1, width + 1):
            value = board[32 * row + col]
            cell = {
                "col": col,
                "row": row,
                "value": "0x%02X" % value,
                "low": value & 0x1F,
                "mine": bool(value & 0x80),
                "opened": bool(value & 0x40),
            }
            cells.append(cell)
            if cell["mine"]:
                mines.append({"col": col, "row": row, "value": cell["value"]})
            else:
                safe.append({"col": col, "row": row})
    return {
        "width": width,
        "height": height,
        "mine_count_current": read_dword(handle, ADDR_MINE_COUNT_CURRENT),
        "timer": read_dword(handle, ADDR_TIMER),
        "opened": read_dword(handle, ADDR_OPENED),
        "safe_total": read_dword(handle, ADDR_SAFE_TOTAL),
        "game_flags": "0x%08X" % (read_dword(handle, ADDR_GAME_FLAGS) & 0xFFFFFFFF),
        "face_state": read_dword(handle, ADDR_FACE_STATE),
        "mine_count_from_board": len(mines),
        "mines": mines,
        "safe_cells": safe,
        "cells": cells,
    }


def make_lparam(x, y):
    return (y << 16) | (x & 0xFFFF)


def cell_center(col, row):
    return 16 * col + 4, 16 * row + 47


def click_cell(hwnd, col, row):
    x, y = cell_center(col, row)
    lp = make_lparam(x, y)
    user32.PostMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp)
    user32.PostMessageW(hwnd, WM_LBUTTONUP, 0, lp)


def capture_window(hwnd, path):
    try:
        from PIL import Image, ImageGrab
    except Exception as exc:
        return {"captured": False, "reason": "PIL unavailable: %s" % exc}

    rect = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return {"captured": False, "reason": "GetWindowRect failed"}
    width = rect.right - rect.left
    height = rect.bottom - rect.top

    hwnd_dc = user32.GetWindowDC(hwnd)
    mem_dc = gdi32.CreateCompatibleDC(hwnd_dc)
    bmp = gdi32.CreateCompatibleBitmap(hwnd_dc, width, height)
    old = gdi32.SelectObject(mem_dc, bmp)
    try:
        printed = user32.PrintWindow(hwnd, mem_dc, 0)
        if printed:
            bmi = BITMAPINFO()
            bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bmi.bmiHeader.biWidth = width
            bmi.bmiHeader.biHeight = -height
            bmi.bmiHeader.biPlanes = 1
            bmi.bmiHeader.biBitCount = 32
            bmi.bmiHeader.biCompression = 0
            buf = ctypes.create_string_buffer(width * height * 4)
            rows = gdi32.GetDIBits(mem_dc, bmp, 0, height, buf, ctypes.byref(bmi), 0)
            if rows:
                img = Image.frombuffer(
                    "RGBA", (width, height), buf, "raw", "BGRA", 0, 1
                ).convert("RGB")
                img.save(path)
                return {
                    "captured": True,
                    "method": "PrintWindow",
                    "path": str(path),
                    "bbox": [rect.left, rect.top, rect.right, rect.bottom],
                }
    finally:
        gdi32.SelectObject(mem_dc, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mem_dc)
        user32.ReleaseDC(hwnd, hwnd_dc)

    user32.SetForegroundWindow(hwnd)
    time.sleep(0.2)
    img = ImageGrab.grab(
        bbox=(rect.left, rect.top, rect.right, rect.bottom)
    ).convert("RGB")
    img.save(path)
    return {
        "captured": True,
        "method": "ImageGrab",
        "path": str(path),
        "bbox": [rect.left, rect.top, rect.right, rect.bottom],
    }


def main():
    if not EXE.is_file():
        raise FileNotFoundError("winmine.exe not found: %s" % EXE)
    actual_sha256 = hashlib.sha256(EXE.read_bytes()).hexdigest().upper()
    if actual_sha256 != EXPECTED_SHA256:
        raise RuntimeError(
            "unexpected winmine.exe SHA256: %s (expected %s)"
            % (actual_sha256, EXPECTED_SHA256)
        )

    OUT_DIR.mkdir(exist_ok=True)
    progress_path = OUT_DIR / "dynamic_verification_progress.json"
    proc = subprocess.Popen([str(EXE)], cwd=str(ROOT))
    hwnd = None
    handle = None
    result = {
        "target": EXE.name,
        "target_sha256": actual_sha256,
        "pid": proc.pid,
    }
    try:
        hwnd, title = find_main_window(proc.pid)
        if not hwnd:
            raise RuntimeError("main window not found")
        result["hwnd"] = int(hwnd)
        result["title"] = title
        handle = open_process(proc.pid)

        initial = read_state(handle)
        result["initial"] = {
            k: v for k, v in initial.items()
            if k not in ("cells", "safe_cells")
        }
        result["initial_safe_count"] = len(initial["safe_cells"])
        progress_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

        for idx, cell in enumerate(initial["safe_cells"], start=1):
            click_cell(hwnd, cell["col"], cell["row"])
            if idx % 10 == 0:
                result["posted_clicks"] = idx
                progress_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            time.sleep(0.01)

        result["posted_clicks"] = len(initial["safe_cells"])
        time.sleep(0.5)
        final = read_state(handle)
        result["final"] = {
            k: v for k, v in final.items()
            if k not in ("cells", "safe_cells")
        }
        result["won"] = final["face_state"] == 3 and final["opened"] == final["safe_total"]
        screenshot_path = OUT_DIR / "winmine_verification.png"
        result["screenshot"] = capture_window(hwnd, screenshot_path)
        if result["screenshot"].get("captured"):
            result["screenshot"]["path"] = screenshot_path.relative_to(ROOT).as_posix()
    finally:
        if handle:
            kernel32.CloseHandle(handle)
        if hwnd:
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.terminate()

    out = OUT_DIR / "dynamic_verification.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
