#!/bin/bash

WORKSPACE="/devel/workspace"
TOOLDIR="$WORKSPACE/tools-current"
TOOLBIN="$TOOLDIR/bin"
SYSBUILD="$WORKSPACE/NetBSD-current-new/usr/src/obj"
SYSROOT="$SYSBUILD/destdir.evbarm"
target="armv7--netbsdelf-eabihf"
MAKE="/usr/bin/gmake"

export PATH="$TOOLBIN:$PATH"
export CPP="$TOOLBIN/$target-cpp"
export CPPFLAGS="-g3 -O0 --sysroot=$SYSROOT"
export CC="$TOOLBIN/$target-gcc"
export CFLAGS="-g3 -O0 --sysroot=$SYSROOT"
export CXX="$TOOLBIN/$target-g++"
export CXXFLAGS="-g3 -O0 --sysroot=$SYSROOT"
./configure --host=$target --target=$target --build=$MACHTYPE
exec $MAKE
