LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := tcsd
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
    svrside.c \
    tcsd_conf.c \
    tcsd_threads.c \
    platform.c	\
    Svrside_binder.cpp

LOCAL_STATIC_LIBRARIES := tcs

LOCAL_LDLIBS := -lz

LOCAL_SHARED_LIBRARIES := libcrypto  libssl libutils libbinder

LOCAL_C_INCLUDES := frameworks/base/include \
	bionic/libstdc++/include \
	bionic \
	$(LOCAL_PATH)/../include
		
$(warning $(LOCAL_C_INCLUDES))
LOCAL_CFLAGS := \
    -DTSS_DEBUG \
    -DRUN_LVL=1 \
    -DPACKAGE_NAME=\"trousers\" \
    -DPACKAGE_TARNAME=\"trousers\" \
    -DPACKAGE_VERSION=\"0.3.6\" \
    -DPACKAGE_STRING=\"trousers\ 0.3.6\" \
    -DPACKAGE_BUGREPORT=\"trousers-tech@lists.sf.net\" \
    -DPACKAGE=\"trousers\" \
    -DVERSION=\"0.3.6\" \
    -DSTDC_HEADERS=1 \
    -DHAVE_SYS_TYPES_H=1 \
    -DHAVE_SYS_STAT_H=1 \
    -DHAVE_STDLIB_H=1 \
    -DHAVE_STRING_H=1 \
    -DHAVE_MEMORY_H=1 \
    -DHAVE_STRINGS_H=1 \
    -DHAVE_INTTYPES_H=1 \
    -DHAVE_STDINT_H=1 \
    -DHAVE_UNISTD_H=1 \
    -DHAVE_OPENSSL_BN_H=1 \
    -DHAVE_OPENSSL_ENGINE_H=1 \
    -DHAVE_PTHREAD_H=1 \
    -DHAVE_DLFCN_H=1 \
    -DLT_OBJDIR=\".libs/\" \
    -DHTOLE_DEFINED=1 \
    -DHAVE_DAEMON=1 \
    -DAPPID=\"TCSD\" \
    -DVAR_PREFIX=\"/usr/local/var\" \
    -DETC_PREFIX=\"/usr/local/etc\" \
    -DTSS_BUILD_PS \
    -DTSS_BUILD_PCR_EVENTS \
    -O0 \
    -DTCSD_DEFAULT_PORT=30003 
    -DTSS_VER_MAJOR=0 \
    -DTSS_VER_MINOR=3 \
    -DTSS_SPEC_MAJOR=1 \
    -DTSS_SPEC_MINOR=2 \
    -Wreturn-type \
    -DBI_OPENSSL \
    -Wall \
    -Werror \
    -Wno-unused-parameter \
    -Wsign-compare
LOCAL_CFLAGS += -DNATIVE_SERVICE -DDEBUG
include $(BUILD_EXECUTABLE)
