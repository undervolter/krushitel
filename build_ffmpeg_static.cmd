@echo off
rem ============================================================
rem  build_ffmpeg_static.cmd - static ffmpeg n8.0.1 build (win64)
rem
rem  Same "min" configure as the shared builds (pulled from
rem  ffbuild/config.log), but --enable-static --disable-shared.
rem  Produces .a libraries + .pc files in ffmpeg-min-win64-static,
rem  consumed by build_win_static.cmd.
rem
rem  Requirements: msys2 (gcc, make) at %MSYS64%
rem  Source:       %FFSRC% (out-of-tree build, shared tree untouched)
rem ============================================================
setlocal
set "MSYS64=C:\Users\tradefall\msys64"
set "FFSRC=C:\Users\tradefall\ffmpeg-src\ffmpeg-8.0.1"
set "FFPREFIX=C:\Users\tradefall\ffmpeg-min-win64-static"
set "FFBUILD=C:\Users\tradefall\ffmpeg-src\build-win64-static"

if not exist "%MSYS64%\usr\bin\bash.exe" goto :nomsys
if not exist "%FFSRC%\configure" goto :nosrc

rem source tree has config.h from previous in-tree builds,
rem which blocks out-of-tree configure -> copy the tree instead
if not exist "%FFBUILD%\configure" (
    echo == copying source tree ==
    robocopy "%FFSRC%" "%FFBUILD%" /E /NFL /NDL /NJH /NJS /NP >nul
    if errorlevel 8 goto :fail
    if not exist "%FFBUILD%\configure" goto :fail
)

echo == ffmpeg static win64 (configure + make) ==
"%MSYS64%\usr\bin\bash.exe" -lc "export PATH=/mingw64/bin:/usr/bin:$PATH; cd '%FFBUILD:\=/%' && make distclean; ./configure --prefix='%FFPREFIX:\=/%' --target-os=mingw32 --arch=x86_64 --disable-everything --disable-doc --disable-programs --disable-network --disable-protocols --disable-demuxers --disable-muxers --enable-static --disable-shared --enable-parser=h264,hevc,mjpeg --enable-decoder=h264,hevc,mjpeg,rawvideo --enable-encoder=mjpeg --enable-bsf=h264_mp4toannexb,hevc_mp4toannexb --disable-autodetect --disable-asm && make -j%NUMBER_OF_PROCESSORS% && make install && cd '%FFPREFIX:\=/%/lib/pkgconfig' && sed -i 's/ -l\(av\|sw\)[a-z]*//g' libav*.pc libsw*.pc"
rem -lav*/-lsw* removed from .pc on purpose: go cgo rejects -Wl flags in
rem pkg-config output, so the ffmpeg archives are linked with whole-archive
rem wrappers via CGO_LDFLAGS in build_win_static.cmd
if errorlevel 1 goto :fail

echo [ok] %FFPREFIX%
endlocal
goto :eof

:nomsys
echo [!] msys2 not found: %MSYS64%\usr\bin\bash.exe
exit /b 1

:nosrc
echo [!] ffmpeg source not found: %FFSRC%\configure
exit /b 1

:fail
echo [!] ffmpeg static build failed - see log above
exit /b 1
