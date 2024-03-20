#
# config.mk
#

LDFLAGS += -Wl,--no-as-needed

ifeq ($(TARGET_BIT),64)
export ARCH := arm64
export TOOLCHAIN_PATH := ~/opt/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu/bin/
export CROSS_COMPILER := aarch64-linux-gnu

else ifeq ($(TARGET_BIT),32)
export ARCH := arm
export TOOLCHAIN_PATH := ~/opt/gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf/bin/
export CROSS_COMPILER := arm-linux-gnueabihf

else
$(error "[ERROR] (TARGET_BIT) Must be defined, ex : make TARGET_BIT=32/64")
endif

