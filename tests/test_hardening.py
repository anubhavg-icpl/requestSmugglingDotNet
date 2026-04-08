#!/usr/bin/env python3
"""
End-to-end validation that SmugglingDefenseModule blocks every attack.

Set Web.config -> Hardening.Enabled = true, restart the app, then run:
    python tests/test_hardening.py 127.0.0.1 8080

For every payload we expect HTTP/1.1 400 with the JSON error
"request rejected by SmugglingDefenseModule".
"""
import socket, sys

HOST, PORT = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("127.0.0.1", 8080)

CASES = {
    "CL+TE both present (CL.TE)": (
        "POST /api/echo.ashx HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        "Content-Length: 13\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n0\r\n\r\nSMUGGLED"
    ),
    "Duplicate Content-Length": (
        "POST /api/echo.ashx HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        "Content-Length: 4\r\n"
        "Content-Length: 5\r\n"
        "\r\nXXXX"
    ),
    "TE: xchunked obfuscation": (
        "POST /api/echo.ashx HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        "Transfer-Encoding: xchunked\r\n"
        "\r\n0\r\n\r\n"
    ),
    "TE with trailing whitespace": (
        "POST /api/echo.ashx HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        "Transfer-Encoding: chunked \r\n"
        "\r\n0\r\n\r\n"
    ),
    "Two TE headers": (
        "POST /api/echo.ashx HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: identity\r\n"
        "\r\n0\r\n\r\n"
    ),
    "Missing Host": (
        "GET /api/echo.ashx HTTP/1.1\r\n\r\n"
    ),
    "Benign GET (must pass)": (
        f"GET /api/echo.ashx HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
    ),
}

def send(req):
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(req.encode())
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    except socket.timeout:
        pass
    s.close()
    return data.decode("latin1", errors="replace")

passed = failed = 0
for name, payload in CASES.items():
    resp = send(payload)
    status = resp.split("\r\n", 1)[0] if resp else "(no response)"
    must_block = name != "Benign GET (must pass)"
    blocked = "400" in status and "SmugglingDefenseModule" in resp
    ok = blocked if must_block else ("200" in status)
    print(f"[{'PASS' if ok else 'FAIL'}] {name:38s} -> {status}")
    if ok: passed += 1
    else:
        failed += 1
        print("        body:", resp[:200].replace("\r", "\\r").replace("\n", "\\n"))

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
