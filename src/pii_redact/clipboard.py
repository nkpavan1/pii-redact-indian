"""Windows clipboard access for secrets (`redact-key export --clip`).

Copies text together with the clipboard formats Windows checks before it
records an item in clipboard history (Win+V) or syncs it to other devices,
so the key doesn't linger there - plain `clip.exe` sets none of them:

- ExcludeClipboardContentFromMonitorProcessing (its presence alone opts out)
- CanIncludeInClipboardHistory = 0
- CanUploadToCloudClipboard = 0

(Microsoft docs: "Clipboard Formats", section "Cloud Clipboard and
Clipboard History Formats".)

Windows only; everything here raises on another platform.
"""

from __future__ import annotations

import ctypes
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

_EXCLUSION_FORMATS = (
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
)
_OPEN_ATTEMPTS = 20
_OPEN_BACKOFF_S = 0.05


def _win32():
    if sys.platform != "win32":
        raise RuntimeError("clipboard support is Windows-only")
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
    ]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.DestroyWindow.restype = wintypes.BOOL
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT
    user32.GetClipboardSequenceNumber.argtypes = []
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD

    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL
    return user32, kernel32


def _last_error() -> OSError:
    return ctypes.WinError(ctypes.get_last_error())


@contextmanager
def _open_clipboard(user32) -> Iterator[None]:
    # A clipboard owner window is required: with a NULL owner,
    # EmptyClipboard leaves the clipboard ownerless and SetClipboardData
    # fails. A hidden STATIC window is the lightest valid owner.
    hwnd = user32.CreateWindowExW(0, "STATIC", None, 0, 0, 0, 0, 0, None, None, None, None)
    if not hwnd:
        raise _last_error()
    try:
        for _ in range(_OPEN_ATTEMPTS):  # another program may hold it briefly
            if user32.OpenClipboard(hwnd):
                break
            time.sleep(_OPEN_BACKOFF_S)
        else:
            raise _last_error()
        try:
            yield
        finally:
            user32.CloseClipboard()
    finally:
        user32.DestroyWindow(hwnd)


def _set_data(user32, kernel32, clipboard_format: int, data: bytes) -> None:
    handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
    if not handle:
        raise _last_error()
    pointer = kernel32.GlobalLock(handle)
    if not pointer:
        error = _last_error()
        kernel32.GlobalFree(handle)
        raise error
    try:
        ctypes.memmove(pointer, data, len(data))
    finally:
        kernel32.GlobalUnlock(handle)
    if not user32.SetClipboardData(clipboard_format, handle):
        error = _last_error()
        kernel32.GlobalFree(handle)
        raise error
    # On success the clipboard owns `handle`; freeing it here would be a bug.


def copy_secret(text: str) -> int:
    """Puts `text` on the clipboard, excluded from clipboard history and
    cloud sync. Returns the clipboard sequence number right after the copy,
    for clear_if_unchanged()."""
    user32, kernel32 = _win32()
    dword_zero = (0).to_bytes(4, "little")
    with _open_clipboard(user32):
        if not user32.EmptyClipboard():
            raise _last_error()
        for name in _EXCLUSION_FORMATS:
            clipboard_format = user32.RegisterClipboardFormatW(name)
            if not clipboard_format:
                raise _last_error()
            _set_data(user32, kernel32, clipboard_format, dword_zero)
        _set_data(user32, kernel32, CF_UNICODETEXT, (text + "\0").encode("utf-16-le"))
    return user32.GetClipboardSequenceNumber()


def clear_if_unchanged(sequence_number: int) -> bool:
    """Empties the clipboard if nothing else was copied since
    copy_secret() - never wipes something the user copied afterwards."""
    user32, _ = _win32()
    if user32.GetClipboardSequenceNumber() != sequence_number:
        return False
    with _open_clipboard(user32):
        user32.EmptyClipboard()
    return True
