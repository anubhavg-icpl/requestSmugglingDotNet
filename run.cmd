@echo off
REM Launch the .NET 4.0 WebForms app under IIS Express on port 8080.
REM Usage: run.cmd            (hardened build, default Web.config)
REM        run.cmd vulnerable  (flips Hardening.Enabled to false first)

setlocal
set APP=%~dp0RequestSmugglingPoC
set IIS="%ProgramFiles%\IIS Express\iisexpress.exe"
if not exist %IIS% set IIS="%ProgramFiles(x86)%\IIS Express\iisexpress.exe"

if "%1"=="vulnerable" (
  powershell -NoProfile -Command "(Get-Content '%APP%\Web.config') -replace 'Hardening.Enabled\" value=\"true', 'Hardening.Enabled\" value=\"false' | Set-Content '%APP%\Web.config'"
  echo [!] Hardening DISABLED -- vulnerable build
) else (
  powershell -NoProfile -Command "(Get-Content '%APP%\Web.config') -replace 'Hardening.Enabled\" value=\"false', 'Hardening.Enabled\" value=\"true' | Set-Content '%APP%\Web.config'"
  echo [+] Hardening ENABLED
)

%IIS% /path:"%APP%" /port:8080 /clr:v4.0
endlocal
