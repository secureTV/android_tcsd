
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TCSPS_H_
#define _TCSPS_H_

#include "tcs_tsp.h"

#include "threads.h"

extern struct key_disk_cache *key_disk_cache_head;
#ifdef NATIVE_SERVICE
struct permission_disk_cache permission_cache_struct;
MUTEX_DECLARE_EXTERN(permission_disk_cache_lock);

#endif
/* file handles for the persistent stores */
extern int system_ps_fd;
/* The lock that surrounds all manipulations of the disk cache */
MUTEX_DECLARE_EXTERN(disk_cache_lock);

int		   get_file();
int		   put_file(int);
void		   close_file(int);
void		   ps_destroy();
#ifdef SOLARIS
TSS_RESULT  read_data(int, void *, UINT32);
TSS_RESULT  write_data(int, void *, UINT32);
#else
inline TSS_RESULT  read_data(int, void *, UINT32);
inline TSS_RESULT  write_data(int, void *, UINT32);
#endif
int		   write_key_init(int, UINT32, UINT32, UINT32);
TSS_RESULT	   cache_key(UINT32, UINT16, TSS_UUID *, TSS_UUID *, UINT16, UINT32, UINT32);
TSS_RESULT	   UnloadBlob_KEY_PS(UINT16 *, BYTE *, TSS_KEY *);
TSS_RESULT	   psfile_get_parent_uuid_by_uuid(int, TSS_UUID *, TSS_UUID *);
TSS_RESULT	   psfile_remove_key_by_uuid(int, TSS_UUID *);
TSS_RESULT	   psfile_get_key_by_uuid(int, TSS_UUID *, BYTE *, UINT16 *);
TSS_RESULT	   psfile_get_key_by_cache_entry(int, struct key_disk_cache *, BYTE *, UINT16 *);
TSS_RESULT	   psfile_get_ps_type_by_uuid(int, TSS_UUID *, UINT32 *);
TSS_RESULT	   psfile_get_vendor_data(int, struct key_disk_cache *, UINT32 *, BYTE **);
TSS_RESULT	   psfile_is_pub_registered(int, TCPA_STORE_PUBKEY *, TSS_BOOL *);
TSS_RESULT	   psfile_get_uuid_by_pub(int, TCPA_STORE_PUBKEY *, TSS_UUID **);
TSS_RESULT	   psfile_write_key(int, TSS_UUID *, TSS_UUID *, UINT32 *, BYTE *, UINT32, BYTE *, UINT16);
TSS_RESULT	   psfile_remove_key(int, struct key_disk_cache *);
TCPA_STORE_PUBKEY *psfile_get_pub_by_tpm_handle(int, TCPA_KEY_HANDLE);
TSS_RESULT	   psfile_get_tpm_handle_by_pub(int, TCPA_STORE_PUBKEY *, TCPA_KEY_HANDLE *);
TSS_RESULT	   psfile_get_tcs_handle_by_pub(int, TCPA_STORE_PUBKEY *, TCS_KEY_HANDLE *);
TSS_RESULT	   psfile_get_parent_tcs_handle_by_pub(int, TCPA_STORE_PUBKEY *, TCS_KEY_HANDLE *);
TCPA_STORE_PUBKEY *psfile_get_pub_by_tcs_handle(int, TCS_KEY_HANDLE);
TSS_RESULT	   psfile_get_key_by_pub(int, TCPA_STORE_PUBKEY *, UINT32 *, BYTE **);
TSS_RESULT	   ps_remove_key(TSS_UUID *);
int		   init_disk_cache(int);
int		   close_disk_cache(int);
TSS_RESULT	   clean_disk_cache(int);

TSS_RESULT	   ps_write_key(TSS_UUID *, TSS_UUID *, BYTE *, UINT32, BYTE *, UINT32);
TSS_RESULT	   ps_get_key_by_uuid(TSS_UUID *, BYTE *, UINT16 *);
TSS_RESULT	   ps_get_key_by_cache_entry(struct key_disk_cache *, BYTE *, UINT16 *);
TSS_RESULT	   ps_get_vendor_data(struct key_disk_cache *, UINT32 *, BYTE **);
TSS_RESULT	   ps_init_disk_cache();
void		   ps_close_disk_cache();
TSS_RESULT	   ps_get_key_by_pub(TCPA_STORE_PUBKEY *, UINT32 *, BYTE **);
#ifdef NATIVE_SERVICE
#define APPCOUNTER_OFFSET   3
#define APP_OFFSET  (APPCOUNTER_OFFSET+sizeof(UINT32))
#define WRITE_SUCCESS  0
#define HMAC_AUTH_FAILED  1
#define EUK_NOT_SET  2
#define WRITE_CACHE_FAILED  3

#define OWNERSHIPSIGNAL 0x01
#define AIKSIGNAL 0x02
#define EUSIGNAL 0x03

void writeSignaltoCache(int value);
TSS_BOOL isAIKSetted();
TSS_BOOL isEUSetted();
TSS_BOOL isOwnerShipped();
TSS_BOOL UUID_cmp(TSS_UUID *key_uuid1, TSS_UUID *key_uuid2);
UINT32 ps_get_appnumber();
UINT32 ps_get_allpermissioninfo(UINT32 *appcounter, UINT32 *buf_size, BYTE* buf);
TSS_BOOL checkPasswd(UINT16 passwdsize, BYTE *passwd);
TSS_RESULT ps_set_permissioninfo(UINT32 UID, UINT16 permissionsize, UINT16 passwdsize, BYTE *permission, BYTE *passwd, BYTE *setresult);
TSS_RESULT	   ps_init_permission_disk_cache();
void		   ps_close_permission_disk_cache();
int get_permission_file();
int put_permission_file(int fd);
int init_permission_disk_cache(int fd);
int close_permission_disk_cache(int fd);
int writePermissiontoFile(struct app_permission_disk_cache *node, UINT16 permissionsize, BYTE *permission);
int addPermissiontoFile(struct app_permission_disk_cache *node, UINT32 UID, UINT16 permissionsize, BYTE *permission);
TSS_BOOL checkAppPermission(int uid, UINT32 ordinal);
void print_file_lock();
#endif
#ifdef TSS_BUILD_PS
#ifdef NATIVE_SERVICE
#define PS_init_disk_cache()	(ps_init_disk_cache() ||ps_init_permission_disk_cache())
#define PS_close_disk_cache()	ps_close_disk_cache();ps_close_permission_disk_cache()
#else
#define PS_init_disk_cache()	ps_init_disk_cache()
#define PS_close_disk_cache()	ps_close_disk_cache()
#endif
#else
#define PS_init_disk_cache()	(TSS_SUCCESS)
#define PS_close_disk_cache()
#endif

#endif
