// RequestSmugglingPoC - .NET Framework 4.0 / WebForms / IHttpHandler
// Five tiny "API" endpoints designed for HTTP request smuggling KBA labs.
//
// This file also defines SmugglingDefenseModule -- the "fix" half of the lab.
// Toggle it via Web.config appSetting "Hardening.Enabled" (true|false).
using System;
using System.Configuration;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;

namespace RequestSmugglingPoC
{
    internal static class Util
    {
        public static string ReadBody(HttpContext ctx)
        {
            ctx.Request.InputStream.Position = 0;
            using (var sr = new StreamReader(ctx.Request.InputStream, Encoding.UTF8))
                return sr.ReadToEnd();
        }

        public static void Json(HttpContext ctx, int status, string body)
        {
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "application/json";
            ctx.Response.Write(body);
        }

        public static string EscapeJson(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder(s.Length + 8);
            foreach (var c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"':  sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n");  break;
                    case '\r': sb.Append("\\r");  break;
                    case '\t': sb.Append("\\t");  break;
                    default:
                        if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }
    }

    // /api/echo.ashx — reflects what the .NET stack actually parsed.
    // Useful as the "back-end" oracle in CL.TE / TE.CL labs.
    public class EchoHandler : IHttpHandler
    {
        public bool IsReusable { get { return true; } }
        public void ProcessRequest(HttpContext ctx)
        {
            var body = Util.ReadBody(ctx);
            var sb = new StringBuilder();
            sb.Append("{\"method\":\"").Append(Util.EscapeJson(ctx.Request.HttpMethod)).Append("\",");
            sb.Append("\"path\":\"").Append(Util.EscapeJson(ctx.Request.RawUrl)).Append("\",");
            sb.Append("\"content_length_hdr\":\"").Append(Util.EscapeJson(ctx.Request.Headers["Content-Length"] ?? "")).Append("\",");
            sb.Append("\"transfer_encoding_hdr\":\"").Append(Util.EscapeJson(ctx.Request.Headers["Transfer-Encoding"] ?? "")).Append("\",");
            sb.Append("\"parsed_body_len\":").Append(body.Length).Append(",");
            sb.Append("\"body\":\"").Append(Util.EscapeJson(body)).Append("\"}");
            Util.Json(ctx, 200, sb.ToString());
        }
    }

    // /api/login.ashx — toy auth. POST username=admin&password=admin
    public class LoginHandler : IHttpHandler
    {
        public bool IsReusable { get { return true; } }
        public void ProcessRequest(HttpContext ctx)
        {
            var u = ctx.Request.Form["username"];
            var p = ctx.Request.Form["password"];
            if (u == "admin" && p == "admin")
            {
                ctx.Response.AppendHeader("Set-Cookie", "session=ADMIN-DEMO-TOKEN; Path=/");
                Util.Json(ctx, 200, "{\"ok\":true,\"role\":\"admin\"}");
            }
            else Util.Json(ctx, 401, "{\"ok\":false}");
        }
    }

    // /api/admin.ashx — "protected". A real front-end proxy would block /api/admin.ashx
    // for unauthenticated users; smuggling lets you reach it on the back-end anyway.
    public class AdminHandler : IHttpHandler
    {
        public bool IsReusable { get { return true; } }
        public void ProcessRequest(HttpContext ctx)
        {
            Util.Json(ctx, 200,
                "{\"secret\":\"FLAG{kba-smuggled-to-admin}\",\"served_by\":\"backend\"}");
        }
    }

    // /api/search.ashx — reflects q. Used to demonstrate response-queue poisoning:
    // a smuggled prefix becomes the start of the *next* victim's request.
    public class SearchHandler : IHttpHandler
    {
        public bool IsReusable { get { return true; } }
        public void ProcessRequest(HttpContext ctx)
        {
            var q = ctx.Request.QueryString["q"] ?? ctx.Request.Form["q"] ?? "";
            Util.Json(ctx, 200, "{\"q\":\"" + Util.EscapeJson(q) + "\"}");
        }
    }

    // /api/status.ashx?sleep=NNNN — used by timing-based smuggling detection.
    public class StatusHandler : IHttpHandler
    {
        public bool IsReusable { get { return true; } }
        public void ProcessRequest(HttpContext ctx)
        {
            int ms = 0;
            int.TryParse(ctx.Request.QueryString["sleep"] ?? "0", out ms);
            if (ms > 0 && ms < 30000) Thread.Sleep(ms);
            Util.Json(ctx, 200, "{\"status\":\"ok\",\"slept_ms\":" + ms + "}");
        }
    }

    // ====================================================================
    //  SmugglingDefenseModule — the "fix"
    // ====================================================================
    //
    // Hooks BeginRequest and rejects (HTTP 400) any request that exhibits
    // a known HTTP request smuggling pre-condition. Mitigations follow
    // PortSwigger's "How to prevent HTTP request smuggling" guidance and
    // RFC 7230 §3.3.3:
    //
    //  1. Reject requests that present BOTH Content-Length AND
    //     Transfer-Encoding headers. RFC 7230 says TE wins, but the only
    //     safe behavior across a proxy chain is to refuse.
    //  2. Reject duplicated Content-Length headers (CL: 5, CL: 6).
    //  3. Reject any Transfer-Encoding value that is not exactly "chunked"
    //     -- catches "xchunked", "chunked, identity", "CHUNKED ", tab/space
    //     obfuscation, and TE: identity smuggling.
    //  4. Reject header NAMES containing whitespace ("Transfer-Encoding ")
    //     or non-token chars -- catches "Transfer-Encoding\r\n: chunked".
    //  5. Reject CR or LF embedded inside any header *value*.
    //  6. Require HTTP/1.1 + a Host header (defense in depth).
    //
    // Enabled when appSetting "Hardening.Enabled" == "true" in Web.config.
    public class SmugglingDefenseModule : IHttpModule
    {
        private static readonly Regex TokenRegex =
            new Regex("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$", RegexOptions.Compiled);

        public void Init(HttpApplication app)
        {
            var enabled = ConfigurationManager.AppSettings["Hardening.Enabled"];
            if (!string.Equals(enabled, "true", StringComparison.OrdinalIgnoreCase))
                return;
            app.BeginRequest += OnBeginRequest;
        }

        public void Dispose() { }

        private static void OnBeginRequest(object sender, EventArgs e)
        {
            var app = (HttpApplication)sender;
            var req = app.Request;
            string reason;
            if (!IsSafe(req, out reason))
            {
                var resp = app.Response;
                resp.StatusCode = 400;
                resp.ContentType = "application/json";
                resp.Write("{\"error\":\"request rejected by SmugglingDefenseModule\",\"reason\":\""
                           + Util.EscapeJson(reason) + "\"}");
                resp.AppendHeader("Connection", "close");
                app.CompleteRequest();
            }
        }

        // Test hook: lets the offline test runner exercise the same logic
        // without spinning up IIS. Mirrors IsSafe(HttpRequest) exactly.
        public static bool IsSafeForTest(System.Collections.Specialized.NameValueCollection headers, out string reason)
        {

            // (6) HTTP/1.1 + Host
            if (string.IsNullOrEmpty(headers["Host"]))
            { reason = "missing Host header"; return false; }

            // (4) header names must be valid tokens (no trailing space, no CR/LF)
            for (int i = 0; i < headers.Count; i++)
            {
                var name = headers.GetKey(i);
                if (string.IsNullOrEmpty(name) || !TokenRegex.IsMatch(name))
                { reason = "invalid header name: " + name; return false; }

                // (5) no CR/LF inside any value
                foreach (var v in headers.GetValues(i) ?? new string[0])
                {
                    if (v != null && (v.IndexOf('\r') >= 0 || v.IndexOf('\n') >= 0))
                    { reason = "CR/LF in header value: " + name; return false; }
                }
            }

            var clValues = headers.GetValues("Content-Length");
            var teValues = headers.GetValues("Transfer-Encoding");

            // (1) CL + TE simultaneously => reject
            if (clValues != null && teValues != null)
            { reason = "both Content-Length and Transfer-Encoding present"; return false; }

            // (2) duplicate / conflicting CL
            if (clValues != null)
            {
                if (clValues.Length > 1) { reason = "duplicate Content-Length"; return false; }
                long n;
                if (!long.TryParse(clValues[0].Trim(), out n) || n < 0)
                { reason = "malformed Content-Length"; return false; }
            }

            // (3) TE must be exactly "chunked" (case-insensitive), single value
            if (teValues != null)
            {
                if (teValues.Length > 1) { reason = "multiple Transfer-Encoding headers"; return false; }
                var te = teValues[0];
                if (te != te.Trim()) { reason = "Transfer-Encoding has leading/trailing whitespace"; return false; }
                if (!string.Equals(te, "chunked", StringComparison.OrdinalIgnoreCase))
                { reason = "Transfer-Encoding not 'chunked': " + te; return false; }
            }

            reason = null;
            return true;
        }

        private static bool IsSafe(HttpRequest req, out string reason)
        {
            return IsSafeForTest(req.Headers, out reason);
        }
    }
}
