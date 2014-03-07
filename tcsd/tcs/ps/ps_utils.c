/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined(HAVE_BYTEORDER_H)
#include <sys/byteorder.h>
#elif defined(HTOLE_DEFINED)
#include <endian.h>
#define LE_16 htole16
#define LE_32 htole32
#define LE_64 htole64
#else
#define LE_16(x) (x)
#define LE_32(x) (x)
#define LE_64(x) (x)
#endif
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_int_literals.h"
#include "tcsps.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcslog.h"

struct key_disk_cache *key_disk_cache_head = NULL;
#ifdef NATIVE_SERVICE
struct permission_disk_cache permission_cache_struct;
#endif

#ifdef SOLARIS
TSS_RESULT
#else
inline TSS_RESULT
#endif
read_data(int fd, void *data, UINT32 size)
{
	int rc;

	rc = read(fd, data, size);
	if (rc == -1) {
		LogError("read of %d bytes: %s", size, strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	} else if ((unsigned)rc != size) {
		LogError("read of %d bytes (only %d read)", size, rc);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}


#ifdef SOLARIS
TSS_RESULT
#else
inline TSS_RESULT
#endif
write_data(int fd, void *data, UINT32 size)
{
	int rc;

	rc = write(fd, data, size);
	if (rc == -1) {
		LogError("write of %d bytes: %s", size, strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	} else if ((unsigned)rc != size) {
		LogError("write of %d bytes (only %d written)", size, rc);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}

/*
 * called by write_key_init to find the next available location in the PS file to
 * write a new key to.
 */
int
find_write_offset(UINT32 pub_data_size, UINT32 blob_size, UINT32 vendor_data_size)
{
	struct key_disk_cache *tmp;
	unsigned int offset;

	MUTEX_LOCK(disk_cache_lock);

	tmp = key_disk_cache_head;
	while (tmp) {
		/* if we find a deleted key of the right size, return its offset */
		if (!(tmp->flags & CACHE_FLAG_VALID) &&
		    tmp->pub_data_size == pub_data_size &&
		    tmp->blob_size == blob_size &&
		    tmp->vendor_data_size == vendor_data_size) {
			offset = tmp->offset;
			MUTEX_UNLOCK(disk_cache_lock);
			return offset;
		}
		tmp = tmp->next;
	}

	MUTEX_UNLOCK(disk_cache_lock);

	/* no correctly sized holes */
	return -1;
}

/*
 * move the file pointer to the point where the next key can be written and return
 * that offset
 */
int
write_key_init(int fd, UINT32 pub_data_size, UINT32 blob_size, UINT32 vendor_data_size)
{
	UINT32 num_keys;
	BYTE version;
	int rc, offset;

	/* seek to the PS version */
	rc = lseek(fd, TSSPS_VERSION_OFFSET, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}

	/* go to NUM_KEYS */
	rc = lseek(fd, TSSPS_NUM_KEYS_OFFSET, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}

	/* read the number of keys */
	rc = read(fd, &num_keys, sizeof(UINT32));
	num_keys = LE_32(num_keys);
	if (rc == -1) {
		LogError("read of %zd bytes: %s", sizeof(UINT32), strerror(errno));
		return -1;
	} else if (rc == 0) {
		/* This is the first key being written */
		num_keys = 1;
		version = 1;

		/* seek to the PS version */
		rc = lseek(fd, TSSPS_VERSION_OFFSET, SEEK_SET);
		if (rc == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			return -1;
		}

		/* write out the version info byte */
		if ((rc = write_data(fd, &version, sizeof(BYTE)))) {
			LogError("%s", __FUNCTION__);
			return rc;
		}

		rc = lseek(fd, TSSPS_NUM_KEYS_OFFSET, SEEK_SET);
		if (rc == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			return -1;
		}

                num_keys = LE_32(num_keys);
		if ((rc = write_data(fd, &num_keys, sizeof(UINT32)))) {
			LogError("%s", __FUNCTION__);
			return rc;
		}

		/* return the offset */
		return (TSSPS_NUM_KEYS_OFFSET + sizeof(UINT32));
	}

	/* if there is a hole in the file we can write to, find it */
	offset = find_write_offset(pub_data_size, blob_size, vendor_data_size);

	if (offset != -1) {
		/* we found a hole, seek to it and don't increment the # of keys on disk */
		rc = lseek(fd, offset, SEEK_SET);
	} else {
		/* we didn't find a hole, increment the number of keys on disk and seek
		 * to the end of the file
		 */
		num_keys++;

		/* go to the beginning */
		rc = lseek(fd, TSSPS_NUM_KEYS_OFFSET, SEEK_SET);
		if (rc == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			return -1;
		}
                num_keys = LE_32(num_keys);
		if ((rc = write_data(fd, &num_keys, sizeof(UINT32)))) {
			LogError("%s", __FUNCTION__);
			return rc;
		}

		rc = lseek(fd, 0, SEEK_END);
	}
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}

	/* lseek returns the number of bytes of offset from the beginning of the file */
	return rc;
}

/*
 * add a new cache entry for a written key
 */
TSS_RESULT
cache_key(UINT32 offset, UINT16 flags,
		TSS_UUID *uuid, TSS_UUID *parent_uuid,
		UINT16 pub_data_size, UINT32 blob_size,
		UINT32 vendor_data_size)
{
	struct key_disk_cache *tmp;

	MUTEX_LOCK(disk_cache_lock);

	tmp = key_disk_cache_head;

	for (; tmp; tmp = tmp->next) {
		/* reuse an invalidated key cache entry */
		if (!(tmp->flags & CACHE_FLAG_VALID))
			goto fill_cache_entry;
	}

	tmp = malloc(sizeof(struct key_disk_cache));
	if (tmp == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(struct key_disk_cache));
		MUTEX_UNLOCK(disk_cache_lock);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	tmp->next = key_disk_cache_head;
	key_disk_cache_head = tmp;

fill_cache_entry:
	tmp->offset = offset;
#ifdef TSS_DEBUG
	if (offset == 0)
		LogDebug("Storing key with file offset==0!!!");
#endif
	tmp->flags = flags;
	tmp->blob_size = blob_size;
	tmp->pub_data_size = pub_data_size;
	tmp->vendor_data_size = vendor_data_size;
	memcpy(&tmp->uuid, uuid, sizeof(TSS_UUID));
	memcpy(&tmp->parent_uuid, parent_uuid, sizeof(TSS_UUID));

	MUTEX_UNLOCK(disk_cache_lock);
	return TSS_SUCCESS;
}

/*
 * read into the PS file and return the number of keys
 */
int
get_num_keys_in_file(int fd)
{
	UINT32 num_keys;
	int rc;

	/* go to the number of keys */
	rc = lseek(fd, TSSPS_NUM_KEYS_OFFSET, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return 0;
	}

	rc = read(fd, &num_keys, sizeof(UINT32));
	if (rc < 0) {
		LogError("read of %zd bytes: %s", sizeof(UINT32), strerror(errno));
		return 0;
	} else if ((unsigned)rc < sizeof(UINT32)) {
		num_keys = 0;
	}
        num_keys = LE_32(num_keys);

	return num_keys;
}

/*
 * count the number of valid keys in the cache
 */
int
get_num_keys()
{
	int num_keys = 0;
	struct key_disk_cache *tmp;

	MUTEX_LOCK(disk_cache_lock);

	tmp = key_disk_cache_head;

	for (; tmp; tmp = tmp->next) {
		if (tmp->flags & CACHE_FLAG_VALID)
			num_keys++;
	}

	MUTEX_UNLOCK(disk_cache_lock);
	return num_keys;
}

/*
 * disk store format:
 *
 * TrouSerS 0.2.0 and before:
 * Version 0:                  cached?
 * [UINT32   num_keys_on_disk]
 * [TSS_UUID uuid0           ] yes
 * [TSS_UUID uuid_parent0    ] yes
 * [UINT16   pub_data_size0  ] yes
 * [UINT16   blob_size0      ] yes
 * [UINT16   cache_flags0    ] yes
 * [BYTE[]   pub_data0       ]
 * [BYTE[]   blob0           ]
 * [...]
 *
 * TrouSerS 0.2.1+
 * Version 1:                  cached?
 * [BYTE     PS version = '\1']
 * [UINT32   num_keys_on_disk ]
 * [TSS_UUID uuid0            ] yes
 * [TSS_UUID uuid_parent0     ] yes
 * [UINT16   pub_data_size0   ] yes
 * [UINT16   blob_size0       ] yes
 * [UINT32   vendor_data_size0] yes
 * [UINT16   cache_flags0     ] yes
 * [BYTE[]   pub_data0        ]
 * [BYTE[]   blob0            ]
 * [BYTE[]   vendor_data0     ]
 * [...]
 *
 */
/*
 * read the PS file pointed to by fd and create a cache based on it
 */
int
init_disk_cache(int fd)
{
	UINT32 num_keys = get_num_keys_in_file(fd);
	UINT16 i;
	UINT64 tmp_offset;
	int rc = 0, offset;
	struct key_disk_cache *tmp, *prev = NULL;
	BYTE srk_blob[2048];
	TSS_KEY srk_key;
#ifdef TSS_DEBUG
	int valid_keys = 0;
#endif

	MUTEX_LOCK(disk_cache_lock);

	if (num_keys == 0) {
		key_disk_cache_head = NULL;
		MUTEX_UNLOCK(disk_cache_lock);
		return 0;
	} else {
		key_disk_cache_head = tmp = calloc(1, sizeof(struct key_disk_cache));
		if (tmp == NULL) {
			LogError("malloc of %zd bytes failed.",
						sizeof(struct key_disk_cache));
			rc = -1;
			goto err_exit;
		}
	}

	/* make sure the file pointer is where we expect, just after the number
	 * of keys on disk at the head of the file
	 */
	offset = lseek(fd, TSSPS_KEYS_OFFSET, SEEK_SET);
	if (offset == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		rc = -1;
		goto err_exit;
	}

	for (i=0; i<num_keys; i++) {
		offset = lseek(fd, 0, SEEK_CUR);
		if (offset == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			rc = -1;
			goto err_exit;
		}
		tmp->offset = offset;
#ifdef TSS_DEBUG
		if (offset == 0)
			LogDebug("Storing key with file offset==0!!!");
#endif
		/* read UUID */
		if ((rc = read_data(fd, (void *)&tmp->uuid, sizeof(TSS_UUID)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		/* read parent UUID */
		if ((rc = read_data(fd, (void *)&tmp->parent_uuid, sizeof(TSS_UUID)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		/* pub data size */
		if ((rc = read_data(fd, &tmp->pub_data_size, sizeof(UINT16)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}
                tmp->pub_data_size = LE_16(tmp->pub_data_size);

		//DBG_ASSERT(tmp->pub_data_size <= 2048 && tmp->pub_data_size > 0);

		/* blob size */
		if ((rc = read_data(fd, &tmp->blob_size, sizeof(UINT16)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}
                tmp->blob_size = LE_16(tmp->blob_size);
		DBG_ASSERT(tmp->blob_size <= 4096 && tmp->blob_size > 0);

		/* vendor data size */
		if ((rc = read_data(fd, &tmp->vendor_data_size, sizeof(UINT32)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}
                tmp->vendor_data_size = LE_32(tmp->vendor_data_size);

		/* cache flags */
		if ((rc = read_data(fd, &tmp->flags, sizeof(UINT16)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}
                tmp->flags = LE_16(tmp->flags);

#ifdef TSS_DEBUG
		if (tmp->flags & CACHE_FLAG_VALID)
			valid_keys++;
#endif
		/* fast forward over the pub key */
		offset = lseek(fd, tmp->pub_data_size, SEEK_CUR);
		if (offset == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			rc = -1;
			goto err_exit;
		}

		/* if this is the SRK, load it into memory, since its already loaded in
		 * the chip */
		 /*memcmp maybe error if not set PRAGMA(1)., please use UUID_cmp () instead.add by xlyu*/
		if (!memcmp(&SRK_UUID, &tmp->uuid, sizeof(TSS_UUID))) {
			/* read SRK blob from disk */
			if ((rc = read_data(fd, srk_blob, tmp->blob_size))) {
				LogError("%s", __FUNCTION__);
				goto err_exit;
			}

			tmp_offset = 0;
			if ((rc = UnloadBlob_TSS_KEY(&tmp_offset, srk_blob, &srk_key)))
				goto err_exit;
			/* add to the mem cache */
			if ((rc = mc_add_entry_init(SRK_TPM_HANDLE, SRK_TPM_HANDLE, &srk_key,
						    &SRK_UUID))) {
				LogError("Error adding SRK to mem cache.");
				destroy_key_refs(&srk_key);
				goto err_exit;
			}
			destroy_key_refs(&srk_key);
		} else {
			/* fast forward over the blob */
			offset = lseek(fd, tmp->blob_size, SEEK_CUR);
			if (offset == ((off_t) - 1)) {
				LogError("lseek: %s", strerror(errno));
				rc = -1;
				goto err_exit;
			}

			/* fast forward over the vendor data */
			offset = lseek(fd, tmp->vendor_data_size, SEEK_CUR);
			if (offset == ((off_t) - 1)) {
				LogError("lseek: %s", strerror(errno));
				rc = -1;
				goto err_exit;
			}
		}

		tmp->next = calloc(1, sizeof(struct key_disk_cache));
		if (tmp->next == NULL) {
			LogError("malloc of %zd bytes failed.",
					sizeof(struct key_disk_cache));
			rc = -1;
			goto err_exit;
		}
		prev = tmp;
		tmp = tmp->next;
	}

	/* delete the dangling, unfilled cache entry */
	free(tmp);
	prev->next = NULL;
	rc = 0;
	LogDebug("%s: found %d valid key(s) on disk.\n", __FUNCTION__, valid_keys);

err_exit:
	MUTEX_UNLOCK(disk_cache_lock);
	return rc;
}

int
close_disk_cache(int fd)
{
	struct key_disk_cache *tmp, *tmp_next;

	if (key_disk_cache_head == NULL)
		return 0;

	MUTEX_LOCK(disk_cache_lock);
	tmp = key_disk_cache_head;

	do {
		tmp_next = tmp->next;
		free(tmp);
		tmp = tmp_next;
	} while (tmp);

	MUTEX_UNLOCK(disk_cache_lock);

	return 0;
}


#ifdef NATIVE_SERVICE
int get_status_infile(int fd, TSS_BOOL *isOwnerShip, TSS_BOOL *isAIKSet,TSS_BOOL *isEUSet){
	/* go to the number of keys */
	int rc =-1;
	rc = lseek(fd, 0, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		*isOwnerShip=0;
		*isAIKSet=0;
		*isEUSet=0;
		return 0;
	}
	rc = read(fd, isOwnerShip, sizeof(TSS_BOOL));
	if (rc < 0) {
		*isOwnerShip = 0;
		lseek(fd, 1, SEEK_SET);
	}
	rc = read(fd, isAIKSet, sizeof(TSS_BOOL));
	if (rc < 0) {
		*isAIKSet = 0;
		lseek(fd, 2, SEEK_SET);
	}
	rc = read(fd, isEUSet, sizeof(TSS_BOOL));
	if (rc < 0) {
		*isEUSet = 0;
	}
	return 0;
}
int get_appcounter_infile(int fd){
	/* go to the number of keys */
	int rc =-1;
	int num = 0;
	rc = lseek(fd, APPCOUNTER_OFFSET, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		return 0;
	}
	read(fd, &num, sizeof(UINT32));
	return num;
}
TSS_BOOL get_file_hmac(int fd, BYTE *out){
	int rc =-1;
	rc = lseek(fd, 0, SEEK_END);
	if ((rc == ((off_t) - 1))||(rc < HMAC_LEN)) {
		return FALSE;
	}
	rc = lseek(fd, rc-HMAC_LEN+1, SEEK_SET);
	read(fd, out, HMAC_LEN);
	return TRUE;
}
/*
 * permission disk store format:
 *
 * [TSS_UUID uuid           ] yes
 * [UINT16   uid    ] yes
 * [UINT16   appname_size  ] yes
 * [UINT16   permission_sze      ] yes
 * [UINT32   vendor_data_size    ] yes
 * [BYTE[]   appname      ]
 * [BYTE[]   permission           ]
 * [BYTE[]   vendor_data           ]
 * [...]
 *
 */
/*
 * read the permission PS file pointed to by fd and create a cache based on it
 */
int
init_permission_disk_cache(int fd)
{
	if(fd <0){
		return -1;
	}
	struct app_permission_disk_cache *tmp, *prev = NULL;
	int rc=0,i,offset;
	int valid_app = 0;
	MUTEX_LOCK(permission_disk_cache_lock);
	get_status_infile(fd, &permission_cache_struct.isOwnerShip,  &permission_cache_struct.isAIKSet, &permission_cache_struct.isEUSet);
	permission_cache_struct.appcounter = get_appcounter_infile(fd);
	if(!get_file_hmac(fd, permission_cache_struct.digest)) memset(permission_cache_struct.digest,0,HMAC_LEN);
	if(permission_cache_struct.appcounter <= 0){
		permission_cache_struct.head =NULL;
		goto err_exit;
	}else{
		permission_cache_struct.head = tmp = calloc(1, sizeof(struct app_permission_disk_cache));
		if (tmp == NULL) {
			LogError("malloc of %zd bytes failed.",
						sizeof(struct app_permission_disk_cache));
			rc = -1;
			goto err_exit;
		}
		memset(tmp, 0, sizeof(struct app_permission_disk_cache));
	}

	/* make sure the file pointer is where we expect, just after the number
	 * of keys on disk at the head of the file
	 */
	offset = lseek(fd, APP_OFFSET, SEEK_SET);
	if (offset == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		rc = -1;
		goto err_exit;
	}

	for (i=0; i<permission_cache_struct.appcounter; i++) {
		offset = lseek(fd, 0, SEEK_CUR);
		if (offset == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			rc = -1;
			goto err_exit;
		}
		tmp->offset = offset;
#ifdef TSS_DEBUG
		if (offset == 0)
			LogDebug("Storing key with file offset==0!!!");
#endif
		/* read UUID */
		if ((rc = read_data(fd, (void *)&tmp->uuid, sizeof(TSS_UUID)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		/* read  UID */
		if ((rc = read_data(fd, (void *)&tmp->uid, sizeof(UINT32)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		/* app name data size */
		if ((rc = read_data(fd, &tmp->appname_size, sizeof(UINT16)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		//DBG_ASSERT(tmp->pub_data_size <= 2048 && tmp->pub_data_size > 0);

		/* permission size */
		if ((rc = read_data(fd, &tmp->permission_size, sizeof(UINT16)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}
		/* vendor data size */
		if ((rc = read_data(fd, &tmp->vendor_data_size, sizeof(UINT32)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}
		offset = lseek(fd, tmp->appname_size, SEEK_CUR);
		if (offset == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			rc = -1;
			goto err_exit;
		}
		/* read permission only permission_size bytes*/
		if ((rc = read_data(fd, &tmp->permission, tmp->permission_size))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}
#ifdef READ_DETAIL
		if ((rc = read_data(fd, NULL, TCSD_MAX_NUM-tmp->permission_size))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}
#endif
		tmp->next = calloc(1, sizeof(struct app_permission_disk_cache));
		if (tmp->next == NULL) {
			LogError("malloc of %zd bytes failed.",
					sizeof(struct app_permission_disk_cache));
			rc = -1;
			goto err_exit;
		}
		memset(tmp, 0, sizeof(struct app_permission_disk_cache));
		prev = tmp;
		tmp = tmp->next;
		valid_app++;
	}

	/* delete the dangling, unfilled cache entry */
	free(tmp);
	prev->next = NULL;
	rc = 0;
	LogDebug("%s: found %d valid app(s) on disk.\n", __FUNCTION__, valid_app);

err_exit:
	MUTEX_UNLOCK(permission_disk_cache_lock);
	return rc;
}

int
close_permission_disk_cache(int fd)
{
	struct app_permission_disk_cache *tmp, *tmp_next;

	if (permission_cache_struct.head == NULL)
		return 0;

	MUTEX_LOCK(disk_cache_lock);
	tmp = permission_cache_struct.head;

	do {
		tmp_next = tmp->next;
		free(tmp);
		tmp = tmp_next;
	} while (tmp);

	MUTEX_UNLOCK(disk_cache_lock);

	return 0;
}

#endif
