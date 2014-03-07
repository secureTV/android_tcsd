#ifdef NATIVE_SERVICE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsps.h"

TSS_RESULT
tcsi_AC_GetPermissionList_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TSS_UUID key_uuid,		/* in */
			 BYTE flags,/* in */
			 UINT32 *UIDNUM,/*permission list number*//*in ,out*/
			 UINT32 *permissioninfosize, /*in ,out*/
			 BYTE* permissioninfo /*permission detail list*//*in ,out*/
)		
{
	TSS_RESULT result;
	int result_size =0;
	if(UIDNUM == NULL ||permissioninfosize ==NULL ||permissioninfo ==NULL){
		LogError("bad paras  .\n");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if ((result = ctx_verify_context(hContext)))
		return result;

	/* Check if key is EUK */ 
	if (!UUID_cmp(&key_uuid, &EUK_UUID)) {
		LogError("Failed checking if UUID is EUK.");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if(flags !=0){
		LogError("flags must be 0.");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	
	result_size = ps_get_allpermissioninfo(UIDNUM, permissioninfosize, permissioninfo);
	if(result_size>=0){
		*permissioninfosize = result_size;
		return TSS_SUCCESS;
	}
	else{
		LogError("Error get permission info");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
}

TSS_RESULT
tcsi_AC_SetPermissionList_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TSS_UUID KeyUUID,	/* in */
			 UINT32 UID,		/* in */
			 UINT16 permissionsize,		/* in */
			 UINT16 passwdsize,			/* in */
			 BYTE* permission,		/* in */
			 BYTE * passwd,
			 BYTE *setresult)		/* out */
{
	TSS_RESULT result;
	if ((result = ctx_verify_context(hContext)))
		return result;
	printf("function:%s,line:%d\n",__FUNCTION__,__LINE__);
	/* Check if key is not EUK */ 
	if (!UUID_cmp(&KeyUUID, &EUK_UUID)) {
		LogError("Failed checking if UUID is EUK.");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	/* Go ahead and store it in system persistant storage */
	if ((result = ps_set_permissioninfo(UID, permissionsize, passwdsize, permission, passwd, setresult))) {
		LogError("Error set permission to file");
		return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
tcsi_AC_CheckStatus_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			TPM_BOOL *isOwnerShip,	/* out */
			 TPM_BOOL *isAIKSet,		/* out */
			 TPM_BOOL * isEUSet		/* out */)
{
	TSS_RESULT result;
	if ((result = ctx_verify_context(hContext)))
		return result;
	if(isAIKSetted()==TSS_SUCCESS){
		*isAIKSet =1;
	}
	else{
		*isAIKSet =0;
	}
	if(isEUSetted()==TSS_SUCCESS){
		*isEUSet =1;
	}
	else{
		*isEUSet =0;
	}
	if(isOwnerShipped()==TSS_SUCCESS){
		*isOwnerShip =1;
	}
	else{
		*isOwnerShip =0;
	}
	return TSS_SUCCESS;
}

#endif
