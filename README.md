# dotnet-kba — HTTP Request Smuggling KBA Lab

A self-contained Knowledge-Based Awareness lab built on **.NET Framework 4.0 / WebForms**
to study HTTP request smuggling per PortSwigger's Web Security Academy.

> **Authorized lab use only.** Run on an isolated VM/loopback. Do **not** point the
> test scripts at hosts you don't own.

## Layout

```
RequestSmugglingPoC/        .NET 4.0 WebForms app (5 IHttpHandler "APIs")
  RequestSmugglingPoC.csproj
  Web.config
  Default.aspx
  App_Code/Handlers.cs
  api/{echo,login,admin,search,status}.ashx
tests/                      Python 3 raw-socket smuggling probes
  detect_timing.py          PortSwigger timing-based detection
  smuggle_clte.py           Basic CL.TE
  smuggle_tecl.py           Basic TE.CL — exfils FLAG from /api/admin.ashx
  smuggle_tete.py           TE.TE obfuscation sweep
  run_all.sh                Run them all
```

## API endpoints (back-end)

| Path                    | Purpose                                              |
|-------------------------|------------------------------------------------------|
| `GET/POST /api/echo.ashx`   | Reflects method, headers, parsed body — back-end oracle |
| `POST /api/login.ashx`      | Toy login (`admin`/`admin`)                          |
| `GET  /api/admin.ashx`      | "Protected" — returns `FLAG{kba-smuggled-to-admin}`  |
| `GET  /api/search.ashx?q=`  | Reflects `q` (response-queue poisoning target)       |
| `GET  /api/status.ashx?sleep=N` | Sleeps N ms — used by timing detection           |

## Build & run the .NET 4.0 app

You need **.NET Framework 4.0** + IIS Express (Windows) or **mono / xsp4** (Linux).

### Windows (IIS Express)
```cmd
cd RequestSmugglingPoC
"%ProgramFiles%\IIS Express\iisexpress.exe" /path:%CD% /port:8080 /clr:v4.0
```

### Mono
```bash
cd RequestSmugglingPoC
xsp4 --port 8080 --nonstop
```

App will be at <http://127.0.0.1:8080/Default.aspx>.

## Putting a vulnerable front-end in front

Real request smuggling needs **two** HTTP parsers that disagree. .NET alone
acts as the back-end; add a front-end proxy that disagrees on CL/TE:

- **HAProxy < 2.0** with `option http-tunnel` — classic CL.TE/TE.CL targets.
- **nginx** with a deliberately permissive `proxy_http_version 1.1` config and
  no `proxy_request_buffering off`.
- **Apache mod_proxy** older 2.4.x for TE.TE practice.

PortSwigger's lab images ship pre-configured if you want a quick canonical front-end.
Point the proxy `upstream` at `127.0.0.1:8080` and run the test scripts against
the proxy port.

## Build & validate the defense (no IIS required)

The hardening module ships with an **offline test runner** that compiles
`SmugglingDefenseModule` with the in-box .NET 4.0 `csc` and exercises every
rule. This is the canonical "build + test" gate.

```cmd
tests\build_and_test.cmd
```
or, from bash / WSL:
```bash
bash tests/build_and_test.sh
```

Expected output:

```
[PASS] CL.TE: CL + TE present                       BLOCKED: both Content-Length and Transfer-Encoding present
[PASS] Duplicate Content-Length                     BLOCKED: duplicate Content-Length
[PASS] TE.TE: xchunked obfuscation                  BLOCKED: Transfer-Encoding not 'chunked': xchunked
[PASS] TE.TE: trailing space on TE value            BLOCKED: Transfer-Encoding has leading/trailing whitespace
[PASS] TE.TE: leading tab on TE value               BLOCKED: Transfer-Encoding has leading/trailing whitespace
[PASS] TE.TE: two TE headers (chunked,identity)     BLOCKED: multiple Transfer-Encoding headers
[PASS] Header value with embedded LF                BLOCKED: CR/LF in header value: X-Foo
[PASS] Header name with trailing space              BLOCKED: invalid header name: Transfer-Encoding
[PASS] Missing Host header                          BLOCKED: missing Host header
[PASS] Malformed Content-Length                     BLOCKED: malformed Content-Length
[PASS] Benign GET                                   ALLOWED
[PASS] Benign POST with Content-Length              ALLOWED
[PASS] Benign chunked POST                          ALLOWED
[PASS] Benign chunked POST (CHUNKED uppercase)      ALLOWED
14 passed, 0 failed
```

## Run the live socket tests

Start the app (Windows + IIS Express):
```cmd
run.cmd                 :: Hardening.Enabled = true   (secure build)
run.cmd vulnerable      :: Hardening.Enabled = false  (KBA demo)
```

Then in another shell:
```bash
# Against the VULNERABLE build, attacks should land:
python tests/detect_timing.py 127.0.0.1 8080
python tests/smuggle_clte.py   127.0.0.1 8080
python tests/smuggle_tecl.py   127.0.0.1 8080   # exfils FLAG{...}
python tests/smuggle_tete.py   127.0.0.1 8080

# Against the HARDENED build, every payload must be rejected with HTTP 400:
python tests/test_hardening.py 127.0.0.1 8080
```

## How is it fixed?

See **[SECURITY.md](SECURITY.md)** for the rule-by-rule explanation,
mapped to PortSwigger's CL.TE / TE.CL / TE.TE attack classes and
RFC 7230 §3.3.3. Short version: the `SmugglingDefenseModule` HttpModule
runs at `BeginRequest` and refuses any request whose length is ambiguous
on the wire.

Indicators of a successful desync:
- `smuggle_clte.py`: the **second** response on the connection has
  `method:"SMUGGLEDGET"` or returns 400/404.
- `smuggle_tecl.py`: response body contains `FLAG{kba-smuggled-to-admin}`
  even though no auth was sent.
- `smuggle_tete.py`: an obfuscation row prints `[!] Possible TE.TE desync`.
- `detect_timing.py`: round-trip > 5 s (back-end ran the smuggled sleep).

## References (PortSwigger Web Security Academy)

- HTTP request smuggling — overview: <https://portswigger.net/web-security/request-smuggling>
- Finding smuggling vulns (timing): <https://portswigger.net/web-security/request-smuggling/finding>
- Lab — basic CL.TE: <https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te>
- Lab — basic TE.CL: <https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl>
- Bypass front-end controls (CL.TE): <https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te>
- HTTP Request Smuggler (Burp ext): <https://github.com/PortSwigger/http-request-smuggler>
