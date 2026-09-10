#!/usr/bin/env bash
# ============================================================
# build_linux_static.sh — статические линукс-сборки krushitel
#
#   linux/amd64 — нативно; cc = zig (musl → полностью статический exe)
#                 или gcc (glibc; NSS-функции могут тянуть libc.so.6)
#   linux/arm64 — zig (musl) или aarch64-linux-gnu-gcc
#
# Требует статический ffmpeg (build_ffmpeg_static_linux.sh):
#   ~/ffmpeg-min-linux64-static / ~/ffmpeg-min-linuxarm64-static
#
# Трюк линковки тот же, что на Windows: архивы ffmpeg перечислены ×3
# (один проход ld по статическому .a не подтягивает члены, на которые
# ссылаются другие члены того же архива; повторы это лечат, дублей не
# дают), системные либы остаются в .pc.
#
# Если линк пойдёт по кэшу cgo со старым PKG_CONFIG_PATH — go clean -cache.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

P64="${FF_LINUX64_STATIC:-$HOME/ffmpeg-min-linux64-static}"
PARM="${FF_LINUXARM64_STATIC:-$HOME/ffmpeg-min-linuxarm64-static}"
ZIG="$(command -v zig 2>/dev/null || true)"
ARMGCC="$(command -v aarch64-linux-gnu-gcc 2>/dev/null || true)"

need() { command -v "$1" >/dev/null 2>&1; }
need go || { echo "[!] go не установлен (sudo apt install golang-go)"; exit 1; }
need pkg-config || { echo "[!] pkg-config не найден (sudo apt install pkg-config)"; exit 1; }
if [ "$(go env GOHOSTOS)" != "linux" ]; then
  echo "[!] это Windows-версия Golang из WSL (interop)."
  echo "    Поставь нативный: sudo apt install golang-go"
  exit 1
fi

FFLIBS="-lavdevice -lavdevice -lavdevice -lavfilter -lavfilter -lavfilter -lavformat -lavformat -lavformat -lavcodec -lavcodec -lavcodec -lswresample -lswresample -lswresample -lswscale -lswscale -lswscale -lavutil -lavutil -lavutil"

build_target() { # $1=goarch $2=ffmpeg-prefix $3=cc(пусто=нативный gcc)
  local goarch=$1 prefix=$2 cc=$3
  if [ ! -f "$prefix/lib/libavcodec.a" ]; then
    echo "[skip] linux/$goarch: нет статического ffmpeg в $prefix"
    echo "       сначала запусти build_ffmpeg_static_linux.sh"
    return 1
  fi
  echo "== linux/$goarch (static) =="
  local envargs=(
    PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
    CGO_ENABLED=1 GOOS=linux GOARCH="$goarch"
    PKG_CONFIG_ALLOW_CROSS=1
    CGO_LDFLAGS="-L$prefix/lib $FFLIBS"
  )
  # CC с аргументами ("zig cc -target ...") обязан быть ОДНИМ argv-элементом
  if [ -n "$cc" ]; then
    envargs+=( CC="$cc" )
  fi
  mkdir -p bin
  env "${envargs[@]}" \
    go build -trimpath -ldflags "-s -w -extldflags '-static'" \
    -o "bin/krushitel_linux_${goarch}" .
  echo "[ok] bin/krushitel_linux_${goarch}"
}

FAIL=0

if [ -n "$ZIG" ]; then
  build_target amd64 "$P64" "zig cc -target x86_64-linux-musl" || FAIL=1
else
  build_target amd64 "$P64" "" || FAIL=1
fi

if [ -n "$ZIG" ]; then
  build_target arm64 "$PARM" "zig cc -target aarch64-linux-musl" || FAIL=1
elif [ -n "$ARMGCC" ]; then
  build_target arm64 "$PARM" "$ARMGCC" || FAIL=1
else
  echo "[skip] linux/arm64: нет ни zig, ни aarch64-linux-gnu-gcc"
fi

echo "============================================"
if [ "${FAIL:-0}" = "1" ]; then
  echo "готово, но часть таргетов не собралась — см. лог выше"
  exit 1
fi
echo "[ok] статические линукс-бинарки готовы (без .so)"
echo "[i] проверка: file bin/krushitel_linux_* → должно быть 'statically linked'"