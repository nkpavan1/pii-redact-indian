"""The Win32 call sequence in pii_redact.clipboard, against a recording fake
of user32/kernel32 - so the tests never touch the real clipboard. The parts
worth pinning down are the ones that are easy to get subtly wrong: memory
ownership (freed only when SetClipboardData fails), the history/cloud
exclusion formats, and always closing the clipboard."""

import ctypes

import pytest

from pii_redact import clipboard


class _FakeWin32:
    def __init__(self, fail_set_for=None):
        self.buffers = {}
        self.clipboard = {}
        self.freed = []
        self.events = []
        self.sequence = 100
        self._next_handle = 1
        self._fail_set_for = fail_set_for
        self._formats = {}

    # user32
    def CreateWindowExW(self, *args):
        self.events.append("create_window")
        return 555

    def DestroyWindow(self, hwnd):
        self.events.append("destroy_window")
        return 1

    def OpenClipboard(self, hwnd):
        self.events.append(("open", hwnd))
        return 1

    def CloseClipboard(self):
        self.events.append("close")
        return 1

    def EmptyClipboard(self):
        self.clipboard.clear()
        self.sequence += 1
        return 1

    def RegisterClipboardFormatW(self, name):
        return self._formats.setdefault(name, 0xC000 + len(self._formats))

    def SetClipboardData(self, clipboard_format, handle):
        if clipboard_format == self._fail_set_for:
            return 0
        self.clipboard[clipboard_format] = bytes(self.buffers[handle])
        self.sequence += 1
        return handle

    def GetClipboardSequenceNumber(self):
        return self.sequence

    # kernel32
    def GlobalAlloc(self, flags, size):
        handle = self._next_handle
        self._next_handle += 1
        self.buffers[handle] = ctypes.create_string_buffer(size)
        return handle

    def GlobalLock(self, handle):
        return ctypes.addressof(self.buffers[handle])

    def GlobalUnlock(self, handle):
        return 0

    def GlobalFree(self, handle):
        self.freed.append(handle)
        return 0

    def format_named(self, name):
        return self._formats[name]


@pytest.fixture
def fake(monkeypatch):
    win32 = _FakeWin32()
    monkeypatch.setattr(clipboard, "_win32", lambda: (win32, win32))
    return win32


def test_copies_utf16_text_with_history_and_cloud_exclusions(fake):
    sequence = clipboard.copy_secret("secret-key")

    assert fake.clipboard[clipboard.CF_UNICODETEXT] == "secret-key\0".encode("utf-16-le")
    for name in (
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    ):
        assert fake.clipboard[fake.format_named(name)] == b"\0\0\0\0"
    assert sequence == fake.sequence
    assert fake.freed == []  # the clipboard owns every handle it accepted
    assert fake.events == ["create_window", ("open", 555), "close", "destroy_window"]


def test_a_rejected_handle_is_freed_and_the_clipboard_still_closed(monkeypatch):
    win32 = _FakeWin32(fail_set_for=clipboard.CF_UNICODETEXT)
    monkeypatch.setattr(clipboard, "_win32", lambda: (win32, win32))
    monkeypatch.setattr(clipboard.ctypes, "get_last_error", lambda: 5)

    with pytest.raises(OSError):
        clipboard.copy_secret("secret-key")

    assert len(win32.freed) == 1
    assert win32.events[-2:] == ["close", "destroy_window"]


def test_clear_only_if_nothing_was_copied_since(fake):
    sequence = clipboard.copy_secret("secret-key")
    assert clipboard.clear_if_unchanged(sequence) is True
    assert fake.clipboard == {}

    sequence = clipboard.copy_secret("secret-key")
    fake.sequence += 1  # the user copied something else meanwhile
    assert clipboard.clear_if_unchanged(sequence) is False
    assert fake.clipboard != {}
