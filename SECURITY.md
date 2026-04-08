# Securing .NET Framework 4.0 / WebForms against HTTP request smuggling

This document is the **fix** half of the KBA. It explains *why* each
mitigation in `SmugglingDefenseModule` exists, mapped to the PortSwigger
attack classes the unhardened build is vulnerable to.

> Implementation: `RequestSmugglingPoC/App_Code/Handlers.cs` →
> `class SmugglingDefenseModule : IHttpModule`. Wired in `Web.config`
> under both `<system.web><httpModules>` (classic pipeline) and
> `<system.webServer><modules>` (integrated pipeline). Toggle with the
> `Hardening.Enabled` appSetting.

## Threat model

Request smuggling requires **two HTTP/1.1 parsers** in the request path
that disagree on where a request ends. PortSwigger groups the disagreements
into three families — every one of them is killed by enforcing a single
rule: **the request length must be unambiguous on the wire**.

| PortSwigger class | Root cause                                          | Mitigation in this module |
|-------------------|------------------------------------------------------|---------------------------|
| **CL.TE**         | Front-end uses `Content-Length`, back-end uses `Transfer-Encoding` | Rule 1: reject any request that carries **both** headers |
| **TE.CL**         | Inverse of CL.TE                                     | Rule 1 (same — symmetric) |
| **TE.TE**         | Both sides honor TE, but one is fooled by an obfuscated variant (`xchunked`, ` chunked`, `chunked,identity`, double TE, header-name LFCR, …) | Rule 3 + Rule 4 + Rule 5 |
| Duplicate-CL      | Two `Content-Length` values, parsers pick different one | Rule 2 |
| Header injection / CRLF smuggling | LF inside a header value introduces a forged header on the next hop | Rule 5 |

## The seven rules

The numbers match the comments in `SmugglingDefenseModule.IsSafeForTest`:

1. **Reject `Content-Length` + `Transfer-Encoding` together.** RFC 7230 §3.3.3
   says TE wins, but the only safe behavior across an arbitrary proxy chain
   is `400 Bad Request`. PortSwigger explicitly recommends this.
2. **Reject duplicate `Content-Length`.** Two values let CL.CL desync.
3. **`Transfer-Encoding` must be exactly `chunked` (case-insensitive),
   single value, no surrounding whitespace.** Kills `xchunked`,
   `chunked, identity`, `\tchunked`, `chunked `, etc.
4. **Header *names* must be RFC 7230 tokens.** Catches
   `Transfer-Encoding ` (trailing space) and `Transfer-Encoding\r\n: chunked`
   (header-name fold).
5. **No raw CR or LF inside any header value.** Catches response-splitting
   and TE-inside-value smuggling.
6. **Require `Host` header.** Defense in depth — missing Host on HTTP/1.1
   is already malformed.
7. **(Implicit) `Content-Length` must be a non-negative integer.** Catches
   `Content-Length: abc` and signed-overflow tricks.

## Things this module deliberately does NOT do

- **HTTP/2 downgrade smuggling.** That's a front-end-side problem. If your
  edge terminates HTTP/2 and re-emits HTTP/1.1 to the .NET app, fix it at
  the edge — see PortSwigger's "HTTP/2 downgrade smuggling" labs.
- **Protect a vulnerable proxy in front of you.** This module is the
  back-end half. The standard guidance from PortSwigger applies in full:
  *use HTTP/2 end-to-end where possible, and disable downgrading*.

## Operational hardening (Web.config)

```xml
<system.web>
  <httpRuntime targetFramework="4.0"
               enableVersionHeader="false"
               maxRequestLength="4096"
               executionTimeout="30"/>
</system.web>
<system.webServer>
  <security>
    <requestFiltering>
      <requestLimits maxAllowedContentLength="1048576"/>
      <verbs allowUnlisted="false">
        <add verb="GET"  allowed="true"/>
        <add verb="POST" allowed="true"/>
      </verbs>
    </requestFiltering>
  </security>
</system.webServer>
```

The `<verbs allowUnlisted="false">` block alone defeats the `GPOST`
smuggled prefix used by `tests/smuggle_tecl.py` — IIS rejects unknown
verbs at the pipeline boundary.

## Validation

Two test layers ship with this lab:

1. **Offline (no IIS required)** — compiles `SmugglingDefenseModule`
   with `csc` and exercises every rule against fabricated header bags.
   ```
   tests\build_and_test.cmd      :: Windows
   bash tests/build_and_test.sh  :: bash / WSL
   ```
   Expected: `14 passed, 0 failed`.

2. **Live (real sockets, against IIS Express)**
   ```
   run.cmd                          :: hardened
   python tests\test_hardening.py   :: must show all PASS
   run.cmd vulnerable
   python tests\smuggle_tecl.py     :: must exfil the FLAG
   ```

## References

- PortSwigger — *How to prevent HTTP request smuggling vulnerabilities*:
  <https://portswigger.net/web-security/request-smuggling#how-to-prevent-http-request-smuggling-vulnerabilities>
- PortSwigger — *Finding HTTP request smuggling*: <https://portswigger.net/web-security/request-smuggling/finding>
- RFC 7230 §3.3.3 (Message Body Length): <https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.3>
- HTTP Desync Attacks (James Kettle, original paper): <https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn>
