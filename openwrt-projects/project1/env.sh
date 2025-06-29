# 以下内容写入env.sh
# >>> openwrt >>>
export STAGING_DIR="/home/hanphone/openwrt-project-environment/openwrt-sdk-24.10.0/staging_dir"
export TOOLCHAIN_DIR="$STAGING_DIR/toolchain-x86_64_gcc-13.3.0_musl"
export PATH="$TOOLCHAIN_DIR/bin:$PATH"
export TARGET=x86_64-openwrt-linux-musl
export CC=$TOOLCHAIN_DIR/bin/${TARGET}-gcc
export AR=$TOOLCHAIN_DIR/bin/${TARGET}-ar
export RANLIB=$TOOLCHAIN_DIR/bin/${TARGET}-ranlib
# <<< openwrt <<<
