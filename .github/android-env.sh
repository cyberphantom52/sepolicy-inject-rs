#!/bin/bash
# Point cc and cargo at the NDK's clang for one Android target, at the API
# level the README documents, by writing the variables to $GITHUB_ENV.
#   android-env.sh <rust target> <ndk path>
set -euo pipefail
target=$1 ndk=$2
api=30
bin="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
case "$target" in
  armv7-linux-androideabi) clang=armv7a-linux-androideabi$api ;;
  *) clang=$target$api ;;
esac
var=${target//-/_}
upper=$(printf '%s' "$var" | tr '[:lower:]' '[:upper:]')
{
  echo "CC_$var=$bin/$clang-clang"
  echo "CXX_$var=$bin/$clang-clang++"
  echo "AR_$var=$bin/llvm-ar"
  echo "CARGO_TARGET_${upper}_LINKER=$bin/$clang-clang"
  # build.rs reads it to tell whether Bionic has reallocarray, as cargo-ndk's
  # -P sets it.
  echo "ANDROID_PLATFORM=$api"
} >> "$GITHUB_ENV"
