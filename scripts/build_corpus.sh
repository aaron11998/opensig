#!/usr/bin/env bash
# Build libc static archives used as the signature corpus.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); B=$ROOT/build; OUT=$ROOT/build/libs; mkdir -p $OUT
J=$(nproc)
# musl 1.2.5: gcc O0/O2/O3, clang O2
for cc in gcc clang; do for o in O0 O2 O3; do
  [ $cc = clang ] && [ $o != O2 ] && continue
  d=$B/musl-$cc-$o; [ -f $OUT/musl-1.2.5-$cc-$o.a ] && continue
  rm -rf $d; cp -r $B/musl-1.2.5 $d; (cd $d && CC=$cc CFLAGS="-$o" ./configure --disable-shared --prefix=$d/inst >/dev/null && make -j$J >/dev/null 2>&1 && cp lib/libc.a $OUT/musl-1.2.5-$cc-$o.a)
  echo "built musl $cc $o"
done; done
# glibc 2.41 (glibc refuses -O0): gcc O2 and O3
for o in O2 O3; do
  d=$B/glibc-build-$o; [ -f $OUT/glibc-2.41-gcc-$o.a ] && continue
  rm -rf $d; mkdir -p $d; (cd $d && $B/glibc-2.41/configure --prefix=/usr --disable-werror CFLAGS="-$o -g0" >/dev/null && make -j$J >/dev/null 2>&1 && cp libc.a $OUT/glibc-2.41-gcc-$o.a)
  echo "built glibc $o"
done
# distro reference archive (same version the box links against)
cp /usr/lib/x86_64-linux-gnu/libc.a $OUT/glibc-2.41-debian.a
ls -la $OUT
