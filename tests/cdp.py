"""Minimal Chrome DevTools Protocol client (standard library only) for browser tests.

Implements just enough of RFC 6455 WebSocket framing to send commands to a
headless Chromium-based browser (Edge or Chrome) and read their replies.
"""

import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def find_browser() -> Optional[str]:
    candidates = [
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Google", "Chrome", "Application", "chrome.exe"),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    for name in ("microsoft-edge", "google-chrome", "chromium", "chromium-browser"):
        if shutil.which(name):
            return shutil.which(name)
    return None


class Browser:
    """Launches a headless browser with remote debugging and connects to its first page."""

    def __init__(self, port: int, width: int = 1600, height: int = 1200) -> None:
        exe = find_browser()
        if not exe:
            raise RuntimeError("No Edge or Chrome browser found")
        self.profile = tempfile.mkdtemp(prefix="hm-browser-")
        self.proc = subprocess.Popen([exe, "--headless=new", "--disable-gpu", "--no-first-run",
                                      "--no-default-browser-check", f"--remote-debugging-port={port}",
                                      f"--user-data-dir={self.profile}", f"--window-size={width},{height}",
                                      "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 20
        targets: List[Dict[str, Any]] = []
        while time.time() < deadline:
            try:
                targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2))
                if any(t.get("type") == "page" for t in targets):
                    break
            except OSError:
                pass
            time.sleep(0.3)
        page = next(t for t in targets if t.get("type") == "page")
        self.ws = WebSocket(page["webSocketDebuggerUrl"])
        self.next_id = 0
        self.events: List[Dict[str, Any]] = []

    def send(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: float = 30) -> Dict[str, Any]:
        self.next_id += 1
        msg_id = self.next_id
        self.ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv(timeout=max(0.1, deadline - time.time())))
            if msg.get("id") == msg_id:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})
            self.events.append(msg)
        raise TimeoutError(method)

    def eval(self, expr: str, timeout: float = 30) -> Any:
        r = self.send("Runtime.evaluate", {"expression": expr, "awaitPromise": True, "returnByValue": True}, timeout)
        if "exceptionDetails" in r:
            raise RuntimeError(r["exceptionDetails"].get("exception", {}).get("description") or r["exceptionDetails"])
        return r.get("result", {}).get("value")

    def wait_for(self, expr: str, timeout: float = 15, interval: float = 0.25) -> Any:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                last = self.eval(expr)
                if last:
                    return last
            except RuntimeError:
                pass
            time.sleep(interval)
        raise TimeoutError(f"wait_for({expr}) last={last!r}")

    def mouse_drag(self, x1: float, y1: float, x2: float, y2: float, steps: int = 8) -> None:
        self.send("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x1, "y": y1})
        self.send("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x1, "y": y1, "button": "left", "buttons": 1, "clickCount": 1})
        for i in range(1, steps + 1):
            self.send("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x1 + (x2 - x1) * i / steps,
                                                   "y": y1 + (y2 - y1) * i / steps, "button": "left", "buttons": 1})
        self.send("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x2, "y": y2, "button": "left", "buttons": 0, "clickCount": 1})

    def close(self) -> None:
        try:
            self.ws.close()
        finally:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            shutil.rmtree(self.profile, ignore_errors=True)


class WebSocket:
    """Client-side WebSocket: masked text frames out, unmasked frames in."""

    def __init__(self, url: str) -> None:
        u = urlparse(url)
        self.sock = socket.create_connection((u.hostname, u.port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\nUpgrade: websocket\r\n"
                           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.sock.recv(1024)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"WebSocket handshake failed: {head[:80]!r}")
        self.buf = head.split(b"\r\n\r\n", 1)[1]

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("WebSocket closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, text: str, opcode: int = 0x1) -> None:
        payload = text.encode() if isinstance(text, str) else text
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        self.sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def recv(self, timeout: float = 30) -> str:
        self.sock.settimeout(timeout)
        message = b""
        while True:
            b1, b2 = self._read(2)
            opcode, n = b1 & 0x0F, b2 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            payload = self._read(n)
            if opcode == 0x9:          # ping
                self.send(payload, opcode=0xA)
                continue
            if opcode == 0x8:
                raise ConnectionError("WebSocket closed by browser")
            message += payload
            if b1 & 0x80:
                return message.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
