LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := tcs

RPC := tcstp
CRYPTO_PACKAGE := openssl

LOCAL_SRC_FILES := \
	../tddl/tddl.c \
	log.c \
	tcs_caps.c \
	tcs_req_mgr.c \
	tcs_context.c \
	tcsi_context.c \
	tcs_utils.c \
	rpc/tcstp/rpc.c \
	rpc/tcstp/rpc_context.c \
	tcsi_caps_tpm.c \
	rpc/tcstp/rpc_caps_tpm.c \
	tcs_auth_mgr.c \
	tcsi_auth.c \
	rpc/tcstp/rpc_auth.c \
	tcs_pbg.c \
	tcsi_transport.c rpc/$(RPC)/rpc_transport.c \
	tcsi_tick.c rpc/$(RPC)/rpc_tick.c \
	tcsi_counter.c tcs_counter.c rpc/$(RPC)/rpc_counter.c \
	tcsi_random.c rpc/$(RPC)/rpc_random.c \
	tcsi_caps.c rpc/$(RPC)/rpc_caps.c \
	tcsi_dir.c rpc/$(RPC)/rpc_dir.c \
	tcsi_evlog.c tcs_evlog_biosem.c tcs_evlog_imaem.c tcs_evlog.c rpc/$(RPC)/rpc_evlog.c \
	tcsi_sign.c rpc/$(RPC)/rpc_sign.c \
	tcsi_quote.c tcs_quote.c rpc/$(RPC)/rpc_quote.c \
	tcsi_seal.c tcs_seal.c rpc/$(RPC)/rpc_seal.c \
	tcsi_changeauth.c rpc/$(RPC)/rpc_changeauth.c \
	tcsi_bind.c rpc/$(RPC)/rpc_bind.c \
	tcsi_own.c rpc/$(RPC)/rpc_own.c \
	ps/ps_utils.c ps/tcsps.c tcsi_ps.c tcs_ps.c tcs_key_ps.c rpc/$(RPC)/rpc_ps.c \
	tcsi_admin.c rpc/$(RPC)/rpc_admin.c \
	tcsi_aik.c tcs_aik.c rpc/$(RPC)/rpc_aik.c \
	tcsi_ek.c rpc/$(RPC)/rpc_ek.c \
	tcsi_certify.c rpc/$(RPC)/rpc_certify.c \
	tcsi_key.c tcs_key.c tcs_key_mem_cache.c tcs_context_key.c rpc/$(RPC)/rpc_key.c crypto/$(CRYPTO_PACKAGE)/crypto.c \
	tcsi_maint.c rpc/$(RPC)/rpc_maint.c \
	tcsi_migration.c tcs_migration.c rpc/$(RPC)/rpc_migration.c \
	tcsi_pcr.c rpc/$(RPC)/rpc_pcr_extend.c \
	tcsi_selftest.c rpc/$(RPC)/rpc_selftest.c \
	tcsi_nv.c rpc/$(RPC)/rpc_nv.c \
	tcsi_audit.c rpc/$(RPC)/rpc_audit.c \
	tcsi_oper.c rpc/$(RPC)/rpc_oper.c \
	tcsi_delegate.c rpc/$(RPC)/rpc_delegate.c \
	tcsi_quote2.c tcs_quote2.c rpc/$(RPC)/rpc_quote2.c \
	tcsi_cmk.c rpc/$(RPC)/rpc_cmk.c \
	rpc/$(RPC)/rpc_ac.c \
	tcs_permission_ps.c \
	tcsi_ac.c

#LOCAL_STATIC_LIBRARIES := tddl

LOCAL_SHARED_LIBRARIES :=libcrypto  libssl

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include

LOCAL_CFLAGS := \
    -DTSS_DEBUG \
    -DPACKAGE_NAME=\"trousers\" \
    -DPACKAGE_TARNAME=\"trousers\" \
    -DPACKAGE_VERSION=\"0.3.6\" \
    -DPACKAGE_STRING=\"trousers\ 0.3.6\" \
    -DPACKAGE_BUGREPORT=\"trousers-tech@lists.sf.net\" \
    -DPACKAGE=\"trousers\" -DVERSION=\"0.3.6\" \
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
    -DAPPID=\"TCSD\ TCS\" \
    -DVAR_PREFIX=\"/usr/local/var\" \
    -DETC_PREFIX=\"/usr/local/etc\" \
    -DTSS_BUILD_TRANSPORT \
    -DTSS_BUILD_TICK \
    -DTSS_BUILD_COUNTER \
    -DTSS_BUILD_RANDOM \
    -DTSS_BUILD_CAPS \
    -DTSS_BUILD_DIR \
    -DTSS_BUILD_PCR_EVENTS \
    -DTSS_BUILD_SIGN \
    -DTSS_BUILD_QUOTE \
    -DTSS_BUILD_SEAL \
    -DTSS_BUILD_CHANGEAUTH \
    -DTSS_BUILD_BIND \
    -DTSS_BUILD_OWN \
    -DTSS_BUILD_PS \
    -DTSS_BUILD_ADMIN \
    -DTSS_BUILD_AIK \
    -DTSS_BUILD_EK \
    -DTSS_BUILD_CERTIFY \
    -DTSS_BUILD_KEY \
    -DTSS_BUILD_MAINT \
    -DTSS_BUILD_MIGRATION \
    -DTSS_BUILD_PCR_EXTEND \
    -DTSS_BUILD_SELFTEST \
    -DTSS_BUILD_NV \
    -DTSS_BUILD_AUDIT \
    -DTSS_BUILD_SEALX \
    -DTSS_BUILD_TSS12 \
    -DTSS_BUILD_DELEGATION \
    -DTSS_BUILD_QUOTE2 \
    -DTSS_BUILD_CMK \
    -O0 \
    -DTCSD_DEFAULT_PORT=30003 \
    -DTSS_VER_MAJOR=0 \
    -DTSS_VER_MINOR=3 \
    -DTSS_SPEC_MAJOR=1 \
    -DTSS_SPEC_MINOR=2 \
    -Wreturn-type \
    -DBI_OPENSSL \
    -Wall \
    -Wno-unused-parameter \
    -Wsign-compare

LOCAL_CFLAGS += -DNATIVE_SERVICE -DDEBUG
include $(BUILD_STATIC_LIBRARY)
