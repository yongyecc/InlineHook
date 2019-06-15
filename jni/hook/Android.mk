LOCAL_PATH := $(call my-dir)  


include $(CLEAR_VARS)

LOCAL_CPPFLAGS +=  -g -O0
LOCAL_ARM_MODE := arm
LOCAL_MODULE    := InlineHook
LOCAL_SRC_FILES := InlineHook.c armshellcode.s thumb2shellcode.s
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

include $(BUILD_STATIC_LIBRARY)
