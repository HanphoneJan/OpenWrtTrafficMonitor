# 基础系统设置
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# 使用环境变量设置SDK路径
if(NOT DEFINED ENV{OPENWRT_SDK})
    set(OPENWRT_SDK "/home/hanphone/openwrt-project-environment/openwrt-sdk-24.10.0")
else()
    set(OPENWRT_SDK $ENV{OPENWRT_SDK})
endif()

set(STAGING_DIR "${OPENWRT_SDK}/staging_dir")
set(ENV{STAGING_DIR} ${STAGING_DIR})  # 关键环境变量

# 自动查找最新工具链
file(GLOB TOOLCHAIN_DIRS "${STAGING_DIR}/toolchain-x86_64_gcc-*")
list(SORT TOOLCHAIN_DIRS)
list(REVERSE TOOLCHAIN_DIRS)
list(GET TOOLCHAIN_DIRS 0 TOOLCHAIN_DIR)

# 设置编译器
set(CMAKE_C_COMPILER "${TOOLCHAIN_DIR}/bin/x86_64-openwrt-linux-gcc")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN_DIR}/bin/x86_64-openwrt-linux-g++")

# 设置sysroot和查找路径
set(CMAKE_SYSROOT "${STAGING_DIR}/target-x86_64_musl")
set(CMAKE_FIND_ROOT_PATH "${CMAKE_SYSROOT}")

# 设置查找策略
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
