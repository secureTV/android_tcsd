LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := tddl
LOCAL_SRC_FILES := tddl.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include

LOCAL_CFLAGS := \
    -DTSS_DEBUG \
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
    -DAPPID=\"TCSD\ TDDL\" \
    -DTCSD_DEFAULT_PORT=30003 \
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

include $(BUILD_STATIC_LIBRARY)