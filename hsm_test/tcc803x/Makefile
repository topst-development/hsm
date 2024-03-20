#
# HSM Test App. Makefile for Linux
#
# Copyright (c) 2021 Telechips Ltd. All Rights Reserved.
#

.SUFFIXES : .c .o

LOCAL_PATH := $(shell pwd)

ifeq ($(YOCTO_BUILD),n)
include ../config.mk
CROSS := $(TOOLCHAIN_PATH)$(CROSS_COMPILER)
CC := $(CROSS)-gcc
LD := $(CROSS)-ld
AR := $(CROSS)-ar
STRIP := $(CROSS)-strip
OUTDIR=out/$(CROSS_COMPILER)
else
OUTDIR=out/
endif

OBJS += \
	$(LOCAL_PATH)/src/hsm_main.o \
	$(LOCAL_PATH)/src/hsm_openssl_cipher.o \
	$(LOCAL_PATH)/src/hsm_cipher_text.o \
	$(LOCAL_PATH)/src/hsm_cipher.o \

INCLUDES += \
	-I$(LOCAL_PATH)/src \
	-I$(LOCAL_PATH)/../hsm_openssl/include \

CFLAGS += \
	-static

LDFLAGS += \
	-L./../hsm_openssl \
	-lpthread \
	-lcrypto$(TARGET_BIT) \

.c.o:
	@$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDES) -O2 -c $< -o $@

TARGET = hsm_test_$(TARGET_BIT)_$(CHIP)


$(TARGET):$(OBJS)
	@$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
	@mkdir -p $(OUTDIR)
	@mv $(TARGET) $(OUTDIR)
	@rm -rf $(OBJS)
	@echo -e "\033[40;32mBUILD COMPLETE\033[0m"

all:$(TARGET)

clean :
	@echo -e "\033[40;32mBUILD CLEAN\033[0m"
	@ rm -rf $(OBJS) $(TARGET)






