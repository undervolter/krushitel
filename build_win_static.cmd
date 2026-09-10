@echo off
rem ============================================================
rem  build_win_static.cmd - STATIC windows/amd64 build of krushitel
rem
rem  Links ffmpeg .a libraries directly into the exe. No ffmpeg
rem  DLLs needed at runtime (only standard system DLLs).
rem
rem  Requirements:
rem    1. gcc in PATH (msys2: pacman -S mingw-w64-x86_64-toolchain)
rem    2. static ffmpeg dev libs from build_ffmpeg_static.cmd
rem
rem  Output: bin\krushitel_windows_amd64_static.exe
rem ============================================================
setlocal
cd /d "%~dp0"

rem toolchain + static win64 ffmpeg (self-contained: ignores ambient env)
if exist "C:\Users\tradefall\msys64\mingw64\bin" set "PATH=C:\Users\tradefall\msys64\mingw64\bin;%PATH%"
if "%FF_WIN64_STATIC%"=="" set "FF_WIN64_STATIC=C:\Users\tradefall\ffmpeg-min-win64-static"
set "PKG_CONFIG_PATH=%FF_WIN64_STATIC%\lib\pkgconfig"

rem .pc files carry only -L + system libs (cgo rejects -Wl there), so the
rem ffmpeg archives are linked via CGO_LDFLAGS here. Each archive is listed
rem 3x: one ld pass over a static .a misses members referenced by other
rem members of the same archive (jpegtables etc); repeats resolve them and
rem duplicate nothing (already-loaded members are skipped). CGO_LDFLAGS is
rem injected twice by cgo, so every archive effectively gets 6 passes.
set "CGO_LDFLAGS=-LC:/Users/tradefall/ffmpeg-min-win64-static/lib -lavdevice -lavdevice -lavdevice -lavfilter -lavfilter -lavfilter -lavformat -lavformat -lavformat -lavcodec -lavcodec -lavcodec -lswresample -lswresample -lswresample -lswscale -lswscale -lswscale -lavutil -lavutil -lavutil"

where gcc >nul 2>nul || goto :nogcc
where pkg-config >nul 2>nul || goto :nopkgconf

pkg-config --exists libavcodec libavutil libswscale libavformat libavfilter libavdevice libswresample
if errorlevel 1 goto :noav

rem sanity: make sure it's really the static build (.a must exist)
if not exist "%FF_WIN64_STATIC%\lib\libavcodec.a" goto :notstatic

if not exist bin mkdir bin

echo == windows/amd64 (static) ==
set CGO_ENABLED=1
set GOOS=windows
set GOARCH=amd64
set CC=gcc

go mod tidy
if errorlevel 1 goto :fail

go build -trimpath -ldflags "-s -w -extldflags '-static'" -o bin\krushitel_windows_amd64_static.exe .
if errorlevel 1 goto :fail

echo [ok] bin\krushitel_windows_amd64_static.exe (no DLLs needed)
endlocal
goto :eof

:nogcc
echo [!] gcc not found in PATH.
echo     msys2: pacman -S mingw-w64-x86_64-toolchain
exit /b 1

:nopkgconf
echo [!] pkg-config not found in PATH (ships with the msys2 toolchain).
exit /b 1

:noav
echo [!] static ffmpeg pkg-config files not found.
echo     run build_ffmpeg_static.cmd first, or set FF_WIN64_STATIC
echo     to a prefix with lib\pkgconfig
exit /b 1

:notstatic
echo [!] %FF_WIN64_STATIC%\lib\libavcodec.a not found - that prefix
echo     looks like a shared build. run build_ffmpeg_static.cmd.
exit /b 1

:fail
echo [!] build failed
rem hint: "undefined reference" to system funcs (bcrypt etc) means
rem Libs.private is incomplete - rerun with e.g.:
rem   set CGO_LDFLAGS=-lbcrypt -lws2_32
rem and rebuild.
exit /b 1
