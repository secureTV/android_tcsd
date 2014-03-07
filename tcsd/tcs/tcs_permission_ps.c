#ifdef NATIVE_SERVICE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/hmac.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsps.h"
#include "req_mgr.h"


TSS_RESULT
ps_init_permission_disk_cache()
{
	int fd;
	TSS_RESULT rc;

	MUTEX_INIT(permission_disk_cache_lock);

	if ((fd = get_permission_file()) < 0)
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if ((rc = init_permission_disk_cache(fd)))
		return rc;

	put_permission_file(fd);
	return TSS_SUCCESS;
}

void
ps_close_permission_disk_cache()
{
	int fd;

	if ((fd = get_permission_file()) < 0) {
		LogError("get_file() failed while trying to close disk cache.");
		return;
	}

	close_permission_disk_cache(fd);

	put_permission_file(fd);
}

TSS_BOOL isAIKSetted(){
	if (permission_cache_struct.isAIKSet ==1)
		return TSS_SUCCESS;
	else
		return TSS_E_FAIL;
}
TSS_BOOL isEUSetted(){
	if (permission_cache_struct.isEUSet ==1)
		return TSS_SUCCESS;
	else
		return TSS_E_FAIL;
}

TSS_BOOL isOwnerShipped(){
	if (permission_cache_struct.isOwnerShip==1)
		return TSS_SUCCESS;
	else
		return TSS_E_FAIL;
}

TSS_BOOL checkIsInit(){
	if (permission_cache_struct.head==NULL)
		return TSS_SUCCESS;
	else
		return TSS_E_FAIL;
}

TSS_BOOL UUID_cmp(TSS_UUID *key_uuid1, TSS_UUID *key_uuid2){
	if(key_uuid1->usTimeMid !=key_uuid2->usTimeMid){
		return FALSE;
	}
	if(key_uuid1->usTimeHigh!=key_uuid2->usTimeHigh){
		return FALSE;
	}
	if(key_uuid1->ulTimeLow!=key_uuid2->ulTimeLow){
		return FALSE;
	}
	if(key_uuid1->bClockSeqHigh!=key_uuid2->bClockSeqHigh){
		return FALSE;
	}
	if(key_uuid1->bClockSeqLow!=key_uuid2->bClockSeqLow){
		return FALSE;
	}
	if(memcmp(key_uuid1->rgbNode, key_uuid2->rgbNode, sizeof(key_uuid1->rgbNode))){
		return FALSE;
	}
	return TRUE;
}

UINT32 ps_get_appnumber(){
	return permission_cache_struct.appcounter;
}

/*uid number+totalsize+(uid+permission_size+permission+uid+permission_size+permission+...),return real buf size:>0 sucess,=0 failed*/
UINT32 ps_get_allpermissioninfo(UINT32 *appcounter, UINT32 *buf_size, BYTE* buf){	
	MUTEX_LOCK(permission_disk_cache_lock);
	int num= permission_cache_struct.appcounter;
	printf("ps_get_allpermissioninfo,line:%d,app num =%d\n", __LINE__, num);
	UINT64 size =0;
	int i = 0;
	UINT32 tmp_buf_size = *buf_size;
	UINT32 total_size =0;
	struct app_permission_disk_cache * tmp;
	if(num <0 ||buf==NULL||appcounter == NULL||buf_size==NULL){
		LogDebug("para error OR no any permission info.\n");
		MUTEX_UNLOCK(permission_disk_cache_lock);
		return -1;
	}
	tmp = permission_cache_struct.head;
	if(tmp == NULL){
		*appcounter = 0;
		*buf_size = 0;
		MUTEX_UNLOCK(permission_disk_cache_lock);
		LogDebug("no any permission info.\n");
		return 0;
	}
	for(i=0;i<num;i++){
		total_size += (sizeof(UINT32)+sizeof(UINT16)+tmp->permission_size);
		tmp= tmp->next;
		if(tmp ==NULL){
			break;
		}
	}
	if(tmp_buf_size<total_size){
		LogDebug("Increasing communication buffer to %d bytes.", total_size);
		buf = realloc(buf, total_size);
		if (buf == NULL) {
			LogError("realloc of %d bytes failed.", total_size);
			MUTEX_UNLOCK(permission_disk_cache_lock);
			return -1;
		}
	}
	tmp = permission_cache_struct.head;
	for(i=0;i<num;i++){
		LoadBlob_UINT32(&size,tmp->uid, buf);
		LoadBlob_UINT16(&size,tmp->permission_size, buf);
		memcpy(buf+size, tmp->permission, tmp->permission_size);
		size+=tmp->permission_size;
		tmp= tmp->next;
		if(tmp ==NULL){
			break;
		}
	}
	MUTEX_UNLOCK(permission_disk_cache_lock);
	if(size !=total_size){
		LogDebug("something error in  permission_cache_struct oprator %d bytes vs %d bytes.\n", total_size, size);
		return -1;
	}
	*appcounter  = num;
	*buf_size = total_size;
	return size;
}

TSS_BOOL  computeFileHMAC(int fd, BYTE *key, UINT16 key_len, BYTE *out){	
	if(fd == -1)return FALSE;
	BYTE buff[4096];
	int ret;
	HMAC_CTX hctx;
	HMAC_CTX_init(&hctx);
	HMAC_Init_ex(&hctx, key, key_len, EVP_sha256(), NULL);
	while((ret = read(fd, buff, sizeof(buff)))>0){
		HMAC_Update(&hctx, buff, ret);
	}
    	HMAC_Final(&hctx, out, NULL);
    	HMAC_CTX_cleanup(&hctx);
	return TRUE;
}
/*calc passwd HMAC at first ,then compute file HMAC from APP_OFFSET to file_length-HMAC_LEN+1*/
TSS_BOOL  computeFileHMACutilOffset(int fd, BYTE *key, UINT16 key_len, BYTE *out,UINT32 offset){	
	if(fd == -1)return FALSE;
	int pos;
	pos = lseek(fd, APPCOUNTER_OFFSET, SEEK_SET);
	if (pos == ((off_t) - 1)) {
		LogError("lseek: %s,calc file HMAC before created", strerror(errno));
		return FALSE;
	}
	BYTE buff[4096];
	UINT32 sum=APPCOUNTER_OFFSET;
	int ret;
	HMAC_CTX hctx;
	memset(out, 0, HMAC_LEN);
	HMAC_CTX_init(&hctx);
	HMAC_Init_ex(&hctx, key, key_len, EVP_sha256(), NULL);
	/*for file created and set permission at first*/
	HMAC_Update(&hctx, key, key_len);
	while((ret = read(fd, buff, sizeof(buff)))>0){
		sum+=ret;
		if(sum> offset){
			if(offset-(sum-ret) == 0) break;
			HMAC_Update(&hctx, buff, offset-(sum-ret));
			break;
		}
		else{
			HMAC_Update(&hctx, buff, ret);
		}
	}
    	HMAC_Final(&hctx, out, NULL);
    	HMAC_CTX_cleanup(&hctx);
	return TRUE;
}

TSS_BOOL compareHMAC(BYTE *pin, int length){
	if (length!=HMAC_LEN) return FALSE;
#ifdef DEBUG
	printf("cache digest\n");
	player_print_hex(permission_cache_struct.digest, HMAC_LEN);
	printf("compute new digest\n");
	player_print_hex(pin, HMAC_LEN);
#endif
	if (memcmp(permission_cache_struct.digest, pin,length)) return FALSE;
	return TRUE;
}

TSS_BOOL checkPasswd(UINT16 passwdsize, BYTE *passwd){
	int fd = -1;
	int rc;
	BYTE out[HMAC_LEN];
	printf("function:%s,line:%d\n",__FUNCTION__,__LINE__);
	printf("checkPasswd,line:%d\n",__LINE__);
	if ((fd = get_permission_file()) < 0)
		return FALSE;
	rc = lseek(fd, 0, SEEK_END);
	if ((rc == ((off_t) - 1))||(rc <(HMAC_LEN-1))) {
		return FALSE;
	}
	rc = lseek(fd, rc-HMAC_LEN, SEEK_SET);
	computeFileHMACutilOffset(fd, passwd, passwdsize, &out[0], rc);
	put_permission_file(fd);
	return compareHMAC(out, HMAC_LEN);
}

TSS_BOOL setPermissiontoCache(UINT32 UID, UINT16 permissionsize, BYTE * permission){
	int i;
	struct app_permission_disk_cache * tmp = permission_cache_struct.head;
	struct app_permission_disk_cache * endnode = permission_cache_struct.head;
	int num = ps_get_appnumber();
	for(i=0;i<num;i++){
		if(tmp->uid == UID){
			memcpy(tmp->permission, permission,permissionsize);
			tmp->permission_size = permissionsize;
			if(writePermissiontoFile(tmp, permissionsize, permission)!=TSS_SUCCESS){
				LogError("writePermissiontoFile failed.");
				return FALSE;
			}
			return TRUE;
		}
		if(tmp->next == NULL){
			endnode = tmp;
		}
		tmp=tmp->next;
	}
	/*no uid equal util  the end,add  a uid permission list*/
	tmp = calloc(1, sizeof(struct app_permission_disk_cache));
	if (tmp == NULL) {
		LogError("malloc of %zd bytes failed.",sizeof(struct app_permission_disk_cache));
		return FALSE;
	}
	memset(tmp, 0, sizeof(struct app_permission_disk_cache));
	tmp->uid = UID;
	if(permission_cache_struct.head==NULL){/*head == null,means first to set; */
		permission_cache_struct.head = tmp; 
		tmp->offset = APP_OFFSET;
	}
	else{
		tmp->offset = endnode->offset+sizeof(TSS_UUID)+sizeof(UINT32)/*uid*/+sizeof(UINT32)/*app_name_size+permission_size*/
			+sizeof(UINT32)/*vendor_data_size*/+endnode->appname_size+TCSD_MAX_NUM+endnode->vendor_data_size;
	}
	memcpy(tmp->permission, permission,permissionsize);
	tmp->permission_size = permissionsize;
	memcpy(&(tmp->uuid), &EUK_UUID, sizeof(TSS_UUID));
	tmp->next = NULL;
	if(endnode!=NULL){
		endnode->next = tmp;
	}
	if(addPermissiontoFile(tmp, UID, permissionsize, permission)!=TSS_SUCCESS){
		LogError("addPermissiontoFile failed.");
		return FALSE;
	}
	return TRUE;
}

TSS_BOOL writeNewHMACtoCache(UINT16 passwdsize, BYTE *passwd){
	struct app_permission_disk_cache * tmp = permission_cache_struct.head;
	struct app_permission_disk_cache * tmp2;
	int fd = -1;
	BYTE  out[HMAC_LEN];
	UINT32 offset;
#ifdef DEBUG
	printf("writeNewHMACtoCache,line:%d\n", __LINE__);
	print_file_lock();
#endif
	if ((fd = get_permission_file()) < 0)
		return FALSE;
	if(tmp==NULL){
		offset = APP_OFFSET;
	}
	else{/*util to end of file except origin HMAC */
		while(tmp!=NULL){
			tmp2 =tmp;
			tmp=tmp->next;
		}
		offset = tmp2->offset+sizeof(TSS_UUID)+sizeof(UINT32)/*uid*/+sizeof(UINT32)/*app_name_size+permission_size*/
				+sizeof(UINT32)/*vendor_data_size*/+tmp2->appname_size+TCSD_MAX_NUM+tmp2->vendor_data_size;
	}
	if(!computeFileHMACutilOffset(fd, passwd, passwdsize, out, offset)){
		put_permission_file(fd);
		return FALSE;
	}
	lseek(fd,offset,SEEK_SET);
	write_data(fd, (void*)out, HMAC_LEN);
	memcpy(permission_cache_struct.digest, out, HMAC_LEN);
	put_permission_file(fd);
	return TRUE;
}

TSS_RESULT ps_set_permissioninfo(UINT32 UID, UINT16 permissionsize, UINT16 passwdsize, BYTE *permission, BYTE *passwd, BYTE *setresult){
	printf("function:%s,line:%d\n",__FUNCTION__,__LINE__);
	MUTEX_LOCK(permission_disk_cache_lock);
	TSS_BOOL  result;
	printf("function:%s,line:%d\n",__FUNCTION__,__LINE__);
	if(isEUSetted()!=TSS_SUCCESS){
		*setresult = EUK_NOT_SET;
		MUTEX_UNLOCK(permission_disk_cache_lock);
		return TCSERR(TSS_E_FAIL);
	}
	if(permissionsize!=0){
		result = checkPasswd(passwdsize, passwd);
		if(!result){
			*setresult = HMAC_AUTH_FAILED;
			MUTEX_UNLOCK(permission_disk_cache_lock);
			return TCSERR(TSS_E_FAIL);
		}
		if( !setPermissiontoCache(UID, permissionsize, permission)){
			*setresult = WRITE_CACHE_FAILED;
			MUTEX_UNLOCK(permission_disk_cache_lock);
			return TCSERR(TSS_E_FAIL);
		}
	}
	else{/*create HMAC need ps file is created first!!*/
		if(checkIsInit()!=TSS_SUCCESS){
			*setresult = WRITE_CACHE_FAILED;
			MUTEX_UNLOCK(permission_disk_cache_lock);
			return TCSERR(TSS_E_FAIL);
		}
	}
	writeNewHMACtoCache(passwdsize, passwd);
	*setresult=WRITE_SUCCESS;
	MUTEX_UNLOCK(permission_disk_cache_lock);
	return TSS_SUCCESS;
}

void writeSignaltoCache(int value){
	MUTEX_LOCK(permission_disk_cache_lock);
	int fd =-1;
	BYTE signal1= 1;
	if ((fd = get_permission_file()) < 0){
		MUTEX_UNLOCK(permission_disk_cache_lock);
		return;
	}
	switch(value){
		case OWNERSHIPSIGNAL:
			lseek(fd, 0, SEEK_SET);
			if (write_data(fd, (void *)&signal1, sizeof(BYTE))==TSS_SUCCESS) {
				permission_cache_struct.isOwnerShip =TRUE;
			}
			break;
		case AIKSIGNAL:
			lseek(fd, 1, SEEK_SET);
			if (write_data(fd, (void *)&signal1, sizeof(BYTE))==TSS_SUCCESS) {
				permission_cache_struct.isAIKSet =TRUE;
			}
			break;
		case EUSIGNAL:
			lseek(fd, 2, SEEK_SET);
			if (write_data(fd, (void *)&signal1, sizeof(BYTE))==TSS_SUCCESS) {
				permission_cache_struct.isEUSet =TRUE;
			}
			break;
		default:
			break;
	}
	put_permission_file(fd);
	MUTEX_UNLOCK(permission_disk_cache_lock);
}


TSS_BOOL checkAppPermission(int uid, UINT32 ordinal){
	MUTEX_LOCK(permission_disk_cache_lock);
	int num = permission_cache_struct.appcounter;
	struct app_permission_disk_cache * tmp = permission_cache_struct.head;
	int i,j;
	if(num == 0||ordinal>TCSD_MAX_NUM||tmp==NULL) goto theend;
	for(i=0;i<num;i++){
		if(tmp->uid == uid){
			for(j=0;j<tmp->permission_size;j++)
			{
				if(tmp->permission[j]==(BYTE)ordinal)
				{
					MUTEX_UNLOCK(permission_disk_cache_lock);
					return TRUE;
				}
			}
		}
		tmp=tmp->next;
	}
theend:
	MUTEX_UNLOCK(permission_disk_cache_lock);
	return FALSE;
}
#endif
