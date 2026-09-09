@echo off
rem ============================================================
rem  release.cmd - pack bin\* into release zips for GitHub Releases.
rem  Run AFTER build_all.cmd. Output: release\krushitel_<ver>_<target>.zip
rem ============================================================
setlocal
cd /d "%~dp0"
set "VER=1.1"

if not exist bin\krushitel_windows_amd64.exe (
    echo [!] no bin\krushitel_windows_amd64.exe - run build_all.cmd first
    exit /b 1
)
if not exist release mkdir release

echo == windows/amd64 ==
powershell -NoProfile -Command "Compress-Archive -Force -Path 'bin\krushitel_windows_amd64.exe','bin\av*.dll','bin\sw*.dll' -DestinationPath 'release\krushitel_%VER%_windows_amd64.zip'"
if errorlevel 1 goto :fail
echo [ok] release\krushitel_%VER%_windows_amd64.zip

if exist bin\win_arm64\krushitel_windows_arm64.exe (
    echo == windows/arm64 ==
    powershell -NoProfile -Command "Compress-Archive -Force -Path 'bin\win_arm64\*' -DestinationPath 'release\krushitel_%VER%_windows_arm64.zip'"
    if errorlevel 1 goto :fail
    echo [ok] release\krushitel_%VER%_windows_arm64.zip
)

if exist bin\linux_amd64\krushitel_linux_amd64 (
    echo == linux/amd64 ==
    powershell -NoProfile -Command "Compress-Archive -Force -Path 'bin\linux_amd64\*' -DestinationPath 'release\krushitel_%VER%_linux_amd64.zip'"
    if errorlevel 1 goto :fail
    echo [ok] release\krushitel_%VER%_linux_amd64.zip
)

if exist bin\linux_arm64\krushitel_linux_arm64 (
    echo == linux/arm64 ==
    powershell -NoProfile -Command "Compress-Archive -Force -Path 'bin\linux_arm64\*' -DestinationPath 'release\krushitel_%VER%_linux_arm64.zip'"
    if errorlevel 1 goto :fail
    echo [ok] release\krushitel_%VER%_linux_arm64.zip
)

echo ============================================
echo  release zips ready in release\
dir /b release\*.zip
endlocal
goto :eof

:fail
echo [!] packing failed
exit /b 1
