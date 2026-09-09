@echo off
rem ============================================================
rem  build_win.cmd — windows/amd64 build of krushitel
rem
rem  Requirements:
rem    1. gcc in PATH (msys2: pacman -S mingw-w64-x86_64-toolchain)
rem    2. pkg-config in PATH (ships with the msys2 toolchain)
rem    3. ffmpeg n8.0 dev libraries visible via pkg-config
rem       (set PKG_CONFIG_PATH to the lib/pkgconfig dir)
rem
rem  Output: bin\krushitel_windows_amd64.exe
rem ============================================================
setlocal
cd /d "%~dp0"

rem toolchain + win64 ffmpeg dev-libs (self-contained: ignores ambient env)
if exist "C:\Users\tradefall\msys64\mingw64\bin" set "PATH=C:\Users\tradefall\msys64\mingw64\bin;%PATH%"
if "%FF_WIN64%"=="" set "FF_WIN64=C:\Users\tradefall\ffmpeg-min-win64"
set "PKG_CONFIG_PATH=%FF_WIN64%\lib\pkgconfig"

where gcc >nul 2>nul || goto :nogcc
where pkg-config >nul 2>nul || goto :nopkgconf

pkg-config --exists libavcodec libavutil libswscale libavformat libavfilter libavdevice libswresample
if errorlevel 1 goto :noav

if not exist bin mkdir bin

echo == windows/amd64 ==
set CGO_ENABLED=1
set GOOS=windows
set GOARCH=amd64
set CC=gcc

go mod tidy
if errorlevel 1 goto :fail
go build -trimpath -ldflags "-s -w" -o bin\krushitel_windows_amd64.exe .
if errorlevel 1 goto :fail

rem copy ffmpeg runtime DLLs next to the exe -> bin\ is self-contained
for /f "delims=" %%p in ('pkg-config --variable=prefix libavcodec') do set FFPREFIX=%%p
rem pkg-config returns forward slashes - copy() chokes on them with wildcards
set "FFPREFIX=%FFPREFIX:/=\%"
copy /y "%FFPREFIX%\bin\*.dll" bin\ >nul 2>nul
if errorlevel 1 echo [warn] DLLs not updated - krushitel is running, close it and rebuild
ver >nul

echo [ok] bin\krushitel_windows_amd64.exe
endlocal
goto :eof

:nogcc
echo [!] gcc not found in PATH.
echo     msys2: pacman -S mingw-w64-x86_64-toolchain
echo     run from the mingw64 shell or add C:\msys64\mingw64\bin to PATH
exit /b 1

:nopkgconf
echo [!] pkg-config not found in PATH (ships with the msys2 toolchain).
exit /b 1

:noav
echo [!] ffmpeg dev libraries not found via pkg-config.
echo     ffmpeg n8.0 required: headers + import libraries (shared build)
echo     and PKG_CONFIG_PATH pointing to the lib/pkgconfig dir.
exit /b 1

:fail
echo [!] build failed
exit /b 1
