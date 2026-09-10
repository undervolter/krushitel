#!/usr/bin/env bash
# ============================================================
# build_ffmpeg_static_linux.sh — статический ffmpeg n8.0.1 (linux)
#
#   linux/amd64 — нативно; cc = zig (musl → krushitel будет полностью
#                 статическим) или gcc (glibc, see build_linux_static.sh)
#   linux/arm64 — zig (musl) или aarch64-linux-gnu-gcc
#
# Флаги — те же "мин", что в shared-сборках, но --enable-static.
# Результат:
#   ~/ffmpeg-min-linux64-static     (.a + .pc)
#   ~/ffmpeg-min-linuxarm64-static
#
# Из .pc вырезаются -lav*/-lsw*: go cgo запрещает -Wl в pkg-config, поэтому
# архивы ffmpeg линкуются через CGO_LDFLAGS (см. build_linux_static.sh).
#
# Запуск: ./build_ffmpeg_static_linux.sh   (на линукс-хосте или в WSL)
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

FFSRC="${FFSRC:-$HOME/ffmpeg-src/ffmpeg-8.0.1}"
BUILDROOT="${FFBUILD_ROOT:-$HOME/ffmpeg-src}"
PREFIX64="${FF_PREFIX64:-$HOME/ffmpeg-min-linux64-static}"
PREFIXARM="${FF_PREFIXARM:-$HOME/ffmpeg-min-linuxarm64-static}"
ZIG="$(command -v zig 2>/dev/null || true)"
ARMGCC="$(command -v aarch64-linux-gnu-gcc 2>/dev/null || true)"

if [ ! -x "$FFSRC/configure" ]; then
  echo "[!] ffmpeg source not found: $FFSRC (override with FFSRC=/path/to/ffmpeg-8.0.1)"
  exit 1
fi

CONFIG="--disable-everything --disable-doc --disable-programs --disable-network
--disable-protocols --disable-demuxers --disable-muxers --enable-static --disable-shared
--enable-parser=h264,hevc,mjpeg --enable-decoder=h264,hevc,mjpeg,rawvideo
--enable-encoder=mjpeg --enable-bsf=h264_mp4toannexb,hevc_mp4toannexb
--disable-autodetect --disable-asm"

# исходник, в дереве которого остался config.h от прошлой сборки, не
# конфигурится out-of-tree — работаем в копии (сам сорц не трогаем)
prepare() { # $1=src $2=build
  if [ -f "$1/config.h" ]; then
    echo "== копия исходника -> $2 (в дереве есть config.h) =="
    rm -rf "$2"
    mkdir -p "$2"
    cp -a "$1/." "$2/"
  else
    mkdir -p "$2"
  fi
}

build_one() { # $1=arch  $2=cc(пусто=нативный gcc)  $3=prefix
  local arch=$1 cc=$2 prefix=$3
  local bd="$BUILDROOT/build-linux${arch}-static"
  prepare "$FFSRC" "$bd"
  echo "== ffmpeg static linux/$arch -> $prefix =="
  (
    cd "$bd"
    make distclean >/dev/null 2>&1 || true
    if [ -n "$cc" ]; then
      ./configure --prefix="$prefix" --enable-cross-compile --target-os=linux \
        --arch="$arch" --cc="$cc" --ar="zig ar" --ranlib="zig ranlib" $CONFIG
    else
      ./configure --prefix="$prefix" --target-os=linux --arch="$arch" $CONFIG
    fi
    make -j"$(nproc)"
    make install
    sed -i 's/ -l\(av\|sw\)[a-z]*//g' \
      "$prefix/lib/pkgconfig"/libav*.pc "$prefix/lib/pkgconfig"/libsw*.pc
  )
}

if [ -n "$ZIG" ]; then
  echo "[i] zig найден — musl, бинарь krushitel будет полностью статическим"
else
  echo "[!] zig не найден — gcc/glibc: krushitel соберётся статиком, но"
  echo "    часть NSS-функций может тянуть libc.so.6 на чужих машинах"
fi

build_one x86_64 "${ZIG:+zig cc -target x86_64-linux-musl}" "$PREFIX64"

if [ -n "$ZIG" ]; then
  build_one aarch64 "zig cc -target aarch64-linux-musl" "$PREFIXARM" \
    || echo "[!] linux/arm64 не собрался — amd64 готов"
elif [ -n "$ARMGCC" ]; then
  build_one aarch64 "$ARMGCC" "$PREFIXARM" \
    || echo "[!] linux/arm64 не собрался — amd64 готов"
else
  echo "[skip] linux/arm64: нет ни zig, ни aarch64-linux-gnu-gcc"
fi

echo -n "[ok] статический ffmpeg готов: $PREFIX64"
if [ -d "$PREFIXARM" ]; then
  echo " + $PREFIXARM"
else
  echo
fi