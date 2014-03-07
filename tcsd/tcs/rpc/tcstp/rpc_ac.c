#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <netdb.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tcs_utils.h"
#include "rpc_tcstp_tcs.h"

TSS_RESULT
tcs_wrap_AC_GetPermissionList(struct tcsd_thread_data *data)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_UUID  key_uuid;
	BYTE  flags;
	TSS_RESULT result;
	UINT32 uidnum;
	UINT32 permissioninfosize =4096;
	BYTE* permissioninfo;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebugFn("thread %ld context %x", THREAD_ID, hContext);

	if (getData(TCSD_PACKET_TYPE_UUID, 1, &key_uuid, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (getData(TCSD_PACKET_TYPE_BYTE, 2, &flags, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	MUTEX_LOCK(tcsp_lock);
	permissioninfo = (BYTE*)malloc(permissioninfosize);
	if(permissioninfo ==NULL){
		LogDebugFn("permissioninfo malloc failed!\n ");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	result = tcsi_AC_GetPermissionList_Internal(hContext, key_uuid, flags, &uidnum, &permissioninfosize, permissioninfo);
	MUTEX_UNLOCK(tcsp_lock);

	if (result == TSS_SUCCESS) {
		initData(&data->comm, 3);
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &uidnum, 0, &data->comm))
			goto error;
		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &permissioninfosize, 0, &data->comm))
			goto error;
		if (setData(TCSD_PACKET_TYPE_PBYTE, 2, permissioninfo, permissioninfosize, &data->comm))
			goto error;
	} else
		initData(&data->comm, 0);
	
	data->comm.hdr.u.result = result;
	free(permissioninfo);
	return TSS_SUCCESS;
error:
	free(permissioninfo);
	return TCSERR(TSS_E_INTERNAL_ERROR);
}
TSS_RESULT
tcs_wrap_AC_SetPermissionList(struct tcsd_thread_data *data)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	TSS_UUID  key_uuid;
	UINT32 uid;
	UINT16 permissionsize;
	UINT16 passwdsize;
	BYTE* permission =NULL;
	BYTE* passwd =NULL;
	BYTE setresult = 0;
	int paraorder;
	printf("function:%s,line:%d\n",__FUNCTION__,__LINE__);
	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebugFn("thread %ld context %x", THREAD_ID, hContext);

	if (getData(TCSD_PACKET_TYPE_UUID, 1, &key_uuid, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &uid, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	
	if (getData(TCSD_PACKET_TYPE_UINT16, 3, &permissionsize, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT16, 4, &passwdsize, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if(permissionsize != 0){
		permission = (BYTE*)malloc(permissionsize);
		if(permission == NULL){
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 5, permission, permissionsize, &data->comm))
			goto error;
	}
	if(passwdsize !=0){
		passwd = (BYTE*)malloc(passwdsize);
		if(passwd == NULL){
			if(permissionsize !=0) free(permission);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if(permissionsize == 0){
			paraorder=5;
		}else{
			paraorder=6;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, paraorder, passwd, passwdsize, &data->comm))
			goto error;
	}
	MUTEX_LOCK(tcsp_lock);

	result = tcsi_AC_SetPermissionList_Internal(hContext, key_uuid, uid, permissionsize, passwdsize,permission, passwd,
			&setresult);

	MUTEX_UNLOCK(tcsp_lock);
	initData(&data->comm, 1);
	if (setData(TCSD_PACKET_TYPE_BYTE, 0, &setresult, 0, &data->comm))
		goto error;
	free(passwd);
	free(permission);
	data->comm.hdr.u.result = result;
	return TSS_SUCCESS;
error:
	free(passwd);
	free(permission);
	return TCSERR(TSS_E_INTERNAL_ERROR);
}
TSS_RESULT
tcs_wrap_AC_CheckStatus(struct tcsd_thread_data *data)
{
	TCS_CONTEXT_HANDLE hContext;
	TPM_BOOL isOwnerShip;
	TPM_BOOL isAIKSet;
	TPM_BOOL isEUSet;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data->comm))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebugFn("thread %ld context %x", THREAD_ID, hContext);

	MUTEX_LOCK(tcsp_lock);

	result = tcsi_AC_CheckStatus_Internal(hContext, &isOwnerShip, &isAIKSet, &isEUSet);

	MUTEX_UNLOCK(tcsp_lock);

	if (result == TSS_SUCCESS) {
		initData(&data->comm, 3);
		if (setData(TCSD_PACKET_TYPE_BOOL, 0, &isOwnerShip, 0, &data->comm))
			return TCSERR(TSS_E_INTERNAL_ERROR);
		if (setData(TCSD_PACKET_TYPE_BOOL, 1, &isAIKSet, 0, &data->comm))
			return TCSERR(TSS_E_INTERNAL_ERROR);
		if (setData(TCSD_PACKET_TYPE_BOOL, 2, &isEUSet, 0, &data->comm))
			return TCSERR(TSS_E_INTERNAL_ERROR);
	} else
		initData(&data->comm, 0);

	data->comm.hdr.u.result = result;
	return TSS_SUCCESS;


}
