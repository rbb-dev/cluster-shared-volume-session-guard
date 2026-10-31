@echo off
setlocal
rem Builds CsvSessionGuard.exe with the in-box .NET Framework compiler.
rem No SDK, no NuGet, no project file. Works on any supported Windows Server.

set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo ERROR: compiler not found at %CSC%
  echo .NET Framework 4.x is required. It is present by default on Windows Server 2012 R2 and later.
  exit /b 1
)

set OUT=%~dp0CsvSessionGuard.exe

"%CSC%" /nologo /target:exe /platform:anycpu /optimize+ /warn:4 ^
  /out:"%OUT%" ^
  /r:System.ServiceProcess.dll /r:System.Core.dll /r:System.Xml.dll ^
  "%~dp0src\CsvSessionGuard.cs" "%~dp0src\CsvSessionGuardTests.cs"

if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)
echo Built %OUT%

echo.
echo Running built-in self-tests ^(no event log, no kernel calls^)...
"%OUT%" -selftest
if errorlevel 1 (
  echo SELF-TESTS FAILED - do not deploy this build
  exit /b 1
)

echo.
echo Build OK and self-tests passed.
echo.
echo Next step, read-only, changes nothing:
echo     CsvSessionGuard.exe -once
echo.
endlocal
