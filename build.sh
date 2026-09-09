#!/usr/bin/env bash
# ============================================================
# build.sh — линукс сборка крушителя
#
# linux/amd64 поддерживается нативно
# linux/arm64 через multiarch, если настроен (gcc-aarch64-linux-gnu + libav*-dev:arm64).
#               
set -euo pipefail
cd "$(dirname "$0")"

need() { command -v "$1" >/dev/null 2>&1; }

need go || {
  echo "[!] go not installed! run: sudo apt install golang-go"
  exit 1
}
if [ "$(go env GOHOSTOS)" != "linux" ]; then
  echo "[!] that's windows version of Golang from WSL (interop)."
  echo "    Run: sudo apt install golang-go"
  exit 1
fi
need pkg-config || {
  echo "[!] pkg-config not found: sudo apt install pkg-config"
  exit 1
}

PKGS="libavcodec libavutil libswscale libavformat libavfilter libavdevice libswresample"
pkg-config --exists $PKGS || {
  echo "[!] ffmpeg dev-libs not found!"
  echo "    sudo apt install libavcodec-dev libavformat-dev libavfilter-dev \\"
  echo "         libavdevice-dev libswscale-dev libswresample-dev libavutil-dev"
  exit 1
}

mkdir -p bin

echo "compiling  -  linux/amd64"
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o bin/krushitel_linux_amd64 .
echo "[ok] bin/krushitel_linux_amd64"

if need aarch64-linux-gnu-gcc \
   && PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig pkg-config --exists $PKGS
then
  echo "compiling  -  linux/arm64"
  env CC=aarch64-linux-gnu-gcc \
      PKG_CONFIG_ALLOW_CROSS=1 \
      PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig \
      CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
      go build -trimpath -ldflags "-s -w" -o bin/krushitel_linux_arm64 .
  echo "[ok] bin/krushitel_linux_arm64"
else
  echo "[skip] linux/arm64: aarch64-linux-gnu-gcc or arm64-version libav not found!"
  echo "       setting multiarch:"
  echo "         sudo dpkg --add-architecture arm64"
  echo "         # in /etc/apt/sources.list restrict amd64-sources [arch=amd64,i386]"
  echo "         # and add arm64 source (ports.ubuntu.com) [arch=arm64,armhf]"
  echo "         sudo apt update"
  echo "         sudo apt install gcc-aarch64-linux-gnu libavcodec-dev:arm64 \\"
  echo "              libavformat-dev:arm64 libavfilter-dev:arm64 libavdevice-dev:arm64 \\"
  echo "              libswscale-dev:arm64 libswresample-dev:arm64 libavutil-dev:arm64"
fi
