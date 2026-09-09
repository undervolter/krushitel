@echo off
rem ============================================================
rem  build_all.cmd - interactive build menu.
rem    windows/amd64   - native (msys2 gcc)
rem    windows/arm64   - cross (llvm-mingw + ffmpeg winarm64)
rem    linux/amd64     - cross (zig cc + ffmpeg linux64)
rem    linux/arm64     - cross (zig cc + ffmpeg linuxarm64)
rem
rem  Runtime libs are copied next to each binary, so every
rem  output folder is self-contained and ready for Releases.
rem ============================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"
set FAIL=0

rem ---- toolchains + ffmpeg (installed at user level) ----
set "MSYS64BIN=C:\Users\tradefall\msys64\mingw64\bin"
set "LLVMMINGWBIN=C:\Users\tradefall\llvm-mingw-20260908-ucrt-x86_64\bin"
set "ZIGDIR=C:\Users\tradefall\zig"
if exist "%MSYS64BIN%" set "PATH=%MSYS64BIN%;%PATH%"
if exist "%LLVMMINGWBIN%" set "PATH=%LLVMMINGWBIN%;%PATH%"
if exist "%ZIGDIR%" set "PATH=%ZIGDIR%;%PATH%"

if "%FF_LINUX64%"==""    set "FF_LINUX64=C:\Users\tradefall\ffmpeg-min-linux64"
if "%FF_LINUXARM64%"=="" set "FF_LINUXARM64=C:\Users\tradefall\ffmpeg-min-linuxarm64"
if "%FF_WINARM64%"==""   set "FF_WINARM64=C:\Users\tradefall\ffmpeg-min-winarm64"
if "%FF_WIN64%"==""      set "FF_WIN64=C:\Users\tradefall\ffmpeg-min-win64"
if "%ZIG%"==""           set "ZIG=%ZIGDIR%\zig.exe"

:menu
echo  ====================================================
echo ^|              krushitel builder                     ^|
echo ^| t.me/kkrushitel   github.com/undervolter/krushitel ^|
echo  ====================================================
echo ^|  1   windows/amd64                                ^|
echo ^|  2   windows/arm64                                ^|
echo ^|  3   linux/amd64                                  ^|
echo ^|  4   linux/arm64                                  ^|
echo  ====================================================
echo ^|  enter   all targets                              ^|
echo ^|  r       pack release zips (release.cmd)          ^|
echo ^|  q       quit                                     ^|
echo  ====================================================
set "CH="
set /p CH=choose: 
if defined CH set "CH=%CH: =%"

if "%CH%"=="1" ( set "DO64=1" & set "DOARM64W=0" & set "DO64L=0" & set "DOARM64L=0" & goto :run )
if "%CH%"=="2" ( set "DO64=0" & set "DOARM64W=1" & set "DO64L=0" & set "DOARM64L=0" & goto :run )
if "%CH%"=="3" ( set "DO64=0" & set "DOARM64W=0" & set "DO64L=1" & set "DOARM64L=0" & goto :run )
if "%CH%"=="4" ( set "DO64=0" & set "DOARM64W=0" & set "DO64L=0" & set "DOARM64L=1" & goto :run )
if /i "%CH%"=="r" ( call release.cmd & goto :menu )
if /i "%CH%"=="q" endlocal & goto :eof
set "DO64=1" & set "DOARM64W=1" & set "DO64L=1" & set "DOARM64L=1"

:run
echo ============================================

rem ---- windows/amd64 (native) ----
if "%DO64%"=="1" (
    call build_win.cmd
    if errorlevel 1 set FAIL=1
)

rem ---- windows/arm64 (llvm-mingw) ----
if "%DOARM64W%"=="1" (
    echo == windows/arm64 ==
    where aarch64-w64-mingw32-gcc >nul 2>nul
    if errorlevel 1 (
        echo [skip] aarch64-w64-mingw32-gcc not found ^(llvm-mingw^) - skipped
    ) else if not exist "%FF_WINARM64%\lib\pkgconfig" (
        echo [skip] %FF_WINARM64%\lib\pkgconfig not found - skipped
    ) else (
        set CGO_ENABLED=1
        set GOOS=windows
        set GOARCH=arm64
        set CC=aarch64-w64-mingw32-gcc
        set PKG_CONFIG_PATH=%FF_WINARM64%\lib\pkgconfig
        set PKG_CONFIG_ALLOW_CROSS=1
        if not exist bin\win_arm64 mkdir bin\win_arm64
        go build -trimpath -ldflags "-s -w" -o bin\win_arm64\krushitel_windows_arm64.exe .
        if errorlevel 1 (
            set FAIL=1
        ) else (
            copy /y "%FF_WINARM64%\bin\*.dll" bin\win_arm64\ >nul 2>nul
            if errorlevel 1 echo [warn] DLLs not updated - close the running app
            ver >nul
            echo [ok] bin\win_arm64\krushitel_windows_arm64.exe
        )
    )
)

rem ---- linux/amd64 (zig cc) ----
if "%DO64L%"=="1" (
    echo == linux/amd64 ==
    if not exist "%ZIG%" (
        echo [skip] zig not found: %ZIG% - skipped
    ) else if not exist "%FF_LINUX64%\lib\pkgconfig" (
        echo [skip] %FF_LINUX64%\lib\pkgconfig not found - skipped
    ) else (
        set CGO_ENABLED=1
        set GOOS=linux
        set GOARCH=amd64
        set CC=%ZIG% cc -target x86_64-linux-gnu
        set PKG_CONFIG_PATH=%FF_LINUX64%\lib\pkgconfig
        set PKG_CONFIG_ALLOW_CROSS=1
        set CGO_LDFLAGS=-Wl,-rpath,$ORIGIN
        if not exist bin\linux_amd64 mkdir bin\linux_amd64
        del /q bin\linux_amd64\lib*.so* 2>nul
        go build -trimpath -ldflags "-s -w" -o bin\linux_amd64\krushitel_linux_amd64 .
        if errorlevel 1 (
            set FAIL=1
        ) else (
            copy /y "%FF_LINUX64%\lib\*.so*" bin\linux_amd64\ >nul 2>nul
            if errorlevel 1 echo [warn] .so not copied
            ver >nul
            echo [ok] bin\linux_amd64\krushitel_linux_amd64
        )
    )
)

rem ---- linux/arm64 (zig cc) ----
if "%DOARM64L%"=="1" (
    echo == linux/arm64 ==
    if not exist "%ZIG%" (
        echo [skip] zig not found - skipped
    ) else if not exist "%FF_LINUXARM64%\lib\pkgconfig" (
        echo [skip] %FF_LINUXARM64%\lib\pkgconfig not found - skipped
    ) else (
        set CGO_ENABLED=1
        set GOOS=linux
        set GOARCH=arm64
        set CC=%ZIG% cc -target aarch64-linux-gnu
        set PKG_CONFIG_PATH=%FF_LINUXARM64%\lib\pkgconfig
        set PKG_CONFIG_ALLOW_CROSS=1
        set CGO_LDFLAGS=-Wl,-rpath,$ORIGIN
        if not exist bin\linux_arm64 mkdir bin\linux_arm64
        del /q bin\linux_arm64\lib*.so* 2>nul
        go build -trimpath -ldflags "-s -w" -o bin\linux_arm64\krushitel_linux_arm64 .
        if errorlevel 1 (
            set FAIL=1
        ) else (
            copy /y "%FF_LINUXARM64%\lib\*.so*" bin\linux_arm64\ >nul 2>nul
            if errorlevel 1 echo [warn] .so not copied
            ver >nul
            echo [ok] bin\linux_arm64\krushitel_linux_arm64
        )
    )
)

:end
echo ============================================
if "%FAIL%"=="1" (
    echo  done, but some targets failed - see log above
) else (
    echo  done
)
echo.
pause
set "FAIL=0"
goto :menu
