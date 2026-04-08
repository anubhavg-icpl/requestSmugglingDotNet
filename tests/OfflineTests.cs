// Offline end-to-end test for SmugglingDefenseModule.
// Builds against the .NET Framework 4.0 csc and runs without IIS.
//
//   csc -nologo -reference:System.Web.dll -reference:System.Configuration.dll \
//       -out:tests/OfflineTests.exe \
//       RequestSmugglingPoC/App_Code/Handlers.cs tests/OfflineTests.cs
//   tests/OfflineTests.exe
//
// (See tests/build_and_test.cmd / tests/build_and_test.sh.)
using System;
using System.Collections.Specialized;
using RequestSmugglingPoC;

class OfflineTests
{
    static int passed, failed;

    static NameValueCollection H(params string[] kv)
    {
        var h = new NameValueCollection();
        for (int i = 0; i < kv.Length; i += 2) h.Add(kv[i], kv[i + 1]);
        return h;
    }

    static void Expect(string name, NameValueCollection h, bool wantSafe)
    {
        string reason;
        bool safe = SmugglingDefenseModule.IsSafeForTest(h, out reason);
        bool ok = safe == wantSafe;
        Console.WriteLine("[{0}] {1,-44} {2}",
            ok ? "PASS" : "FAIL", name,
            safe ? "ALLOWED" : ("BLOCKED: " + reason));
        if (ok) passed++; else failed++;
    }

    static int Main()
    {
        // -------- attacks that MUST be blocked --------
        Expect("CL.TE: CL + TE present",
            H("Host", "x", "Content-Length", "13", "Transfer-Encoding", "chunked"), false);

        Expect("Duplicate Content-Length",
            H("Host", "x", "Content-Length", "4", "Content-Length", "5"), false);

        Expect("TE.TE: xchunked obfuscation",
            H("Host", "x", "Transfer-Encoding", "xchunked"), false);

        Expect("TE.TE: trailing space on TE value",
            H("Host", "x", "Transfer-Encoding", "chunked "), false);

        Expect("TE.TE: leading tab on TE value",
            H("Host", "x", "Transfer-Encoding", "\tchunked"), false);

        Expect("TE.TE: two TE headers (chunked,identity)",
            H("Host", "x", "Transfer-Encoding", "chunked", "Transfer-Encoding", "identity"), false);

        Expect("Header value with embedded LF",
            H("Host", "x", "X-Foo", "bar\nTransfer-Encoding: chunked"), false);

        Expect("Header name with trailing space",
            H("Host", "x", "Transfer-Encoding ", "chunked"), false);

        Expect("Missing Host header",
            H("Content-Length", "0"), false);

        Expect("Malformed Content-Length",
            H("Host", "x", "Content-Length", "abc"), false);

        // -------- benign requests that MUST pass --------
        Expect("Benign GET",
            H("Host", "example.com", "User-Agent", "curl/8.0"), true);

        Expect("Benign POST with Content-Length",
            H("Host", "example.com", "Content-Length", "12", "Content-Type", "application/json"), true);

        Expect("Benign chunked POST",
            H("Host", "example.com", "Transfer-Encoding", "chunked"), true);

        Expect("Benign chunked POST (CHUNKED uppercase)",
            H("Host", "example.com", "Transfer-Encoding", "CHUNKED"), true);

        Console.WriteLine();
        Console.WriteLine("{0} passed, {1} failed", passed, failed);
        return failed == 0 ? 0 : 1;
    }
}
