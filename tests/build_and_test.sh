#!/usr/bin/env bash
# Build SmugglingDefenseModule + offline tests with .NET 4.0 csc, run them.
# No IIS needed. Works in git-bash / WSL on Windows.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CSC="/c/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe"
[ -x "$CSC" ] || CSC="/c/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe"

# csc is a Windows binary -- copy sources to a flat dir to dodge MSYS path mangling
WORK="$(mktemp -d)"
cp "$ROOT/RequestSmugglingPoC/App_Code/Handlers.cs" "$WORK/H.cs"
cp "$ROOT/tests/OfflineTests.cs"                    "$WORK/T.cs"
cd "$WORK"
MSYS_NO_PATHCONV=1 "$CSC" -nologo -target:exe \
  -reference:System.dll -reference:System.Web.dll -reference:System.Configuration.dll \
  -out:OfflineTests.exe H.cs T.cs
./OfflineTests.exe
rc=$?
cp OfflineTests.exe "$ROOT/tests/OfflineTests.exe"
exit $rc
