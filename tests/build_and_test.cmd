@echo off
REM Build SmugglingDefenseModule + offline test runner with .NET 4.0 csc
REM and execute the tests. No IIS / IIS Express required.
setlocal
set ROOT=%~dp0..
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe

"%CSC%" -nologo -target:exe ^
  -reference:System.dll -reference:System.Web.dll -reference:System.Configuration.dll ^
  -out:"%ROOT%\tests\OfflineTests.exe" ^
  "%ROOT%\RequestSmugglingPoC\App_Code\Handlers.cs" ^
  "%ROOT%\tests\OfflineTests.cs"
if errorlevel 1 exit /b 1

"%ROOT%\tests\OfflineTests.exe"
exit /b %errorlevel%
