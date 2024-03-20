#
# Copyright (c) 2013-2016 Telechips All Rights Reserved.


ifneq ($(filter $(TARGET_BOARD_SOC), tcc803x tcc803xp tcc805x),)

LOCAL_PATH:= $(call my-dir)

ifneq ($(filter $(TARGET_BOARD_SOC), tcc803x tcc803xp),)
HSM_CHIP_TYPE = tcc803x
else
HSM_CHIP_TYPE = tcc805x
endif

include $(CLEAR_VARS)
LOCAL_MODULE := libopenssl_crypto
LOCAL_MODULE_SUFFIX := .a
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MODULE_TAGS := optional
LOCAL_PROPRIETARY_MODULE := true
LOCAL_SRC_FILES_32 := hsm_openssl/libcrypto32_android.a
LOCAL_SRC_FILES_64 := hsm_openssl/libcrypto64_android.a
OVERRIDE_BUILT_MODULE_PATH := $(TARGET_OUT_INTERMEDIATE_LIBRARIES)
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE_TARGET_ARCH := arm arm64
LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE_TAGS := optional
LOCAL_ARM_MODE := arm

LOCAL_SHARED_LIBRARIES := \
	libc \
	libc++ \
	liblog \

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/$(HSM_CHIP_TYPE)/src \
    $(LOCAL_PATH)/hsm_openssl/include \
    $(LOCAL_PATH)/hsm_openssl/include/openssl \

LOCAL_CFLAGS := -g -O2

LOCAL_STATIC_LIBRARIES := libopenssl_crypto

LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/bin


LOCAL_SRC_FILES := \
	$(HSM_CHIP_TYPE)/src/hsm_main.c \
	$(HSM_CHIP_TYPE)/src/hsm_cipher_text.c \
	$(HSM_CHIP_TYPE)/src/hsm_openssl_cipher.c

ifneq ($(filter $(TARGET_BOARD_SOC), tcc803x tcc803xp),)
	LOCAL_SRC_FILES += $(HSM_CHIP_TYPE)/src/hsm_cipher.c
endif

LOCAL_MODULE := hsm_test_$(TARGET_BOARD_SOC)

LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)

# end of file Android.mk

endif