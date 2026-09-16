@echo off
rem ============================================================
rem  build_win_static.cmd - PURE GO windows/amd64 build of krushitel
rem
rem  No CGO, no GCC, no MSYS2, no external FFmpeg libs needed!
rem  Decoders (H.264 / H.265) are 100% Pure Go.
rem
rem  Output: bin\krushitel_windows_amd64.exe
rem ============================================================
setlocal
cd /d "%~dp0"

if not exist bin mkdir bin

echo == windows/amd64 (pure Go, CGO_ENABLED=0) ==
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64

go build -trimpath -ldflags="-s -w" -o bin\krushitel_windows_amd64.exe .
if errorlevel 1 (
    echo [!] build failed
    exit /b 1
)

copy /y bin\krushitel_windows_amd64.exe bin\krushitel_windows_amd64_static.exe >nul

echo [ok] bin\krushitel_windows_amd64.exe (pure Go, no DLLs or C-compiler needed)
endlocal

