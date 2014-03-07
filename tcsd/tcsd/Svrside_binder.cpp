#ifdef NATIVE_SERVICE
#include "Svrside_binder.h"
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <utils/Log.h>

using namespace android;
using namespace std;

void player_print_hex(unsigned char *buf, int len)
{
	int i = 0;
	printf("0000\t");
	for ( i=1; i<=len; i++ )
	{
		printf("%02X ", buf[i-1]);
		if ( (i % 8) == 0 && (i%16) != 0)
		{
			printf("-- ");
		}
		if ( (i % 16) == 0)
		{
			printf("\n");
			printf("%04X\t", i/16);
		}
	}
	printf("\n");
}

class TCSDService : public BBinder  
{  
private:  
    //mutable Mutex m_Lock;  
    //int32_t m_NextConnId;  
	 struct tcsd_thread_data *tcsddata;
public:  
	static int getCallingPid() {
		return IPCThreadState::self()->getCallingPid();
	}
	static int getCallingUid() {
		return IPCThreadState::self()->getCallingUid();
	}
	void setCallingID(int pid, int uid){
		if(tcsddata !=NULL){
			tcsddata->callingpid = pid;
			tcsddata->callinguid = uid;
		}
	}
	static int Instance(struct tcsd_thread_data *data){
		printf("TCSDService Instantiate\n");  
		int ret = defaultServiceManager()->addService(  
		String16("tcsdservice"), new TCSDService(data));  
	   	return ret;  
	}
	TCSDService(struct tcsd_thread_data *data){
		tcsddata = data;
	}
	virtual ~TCSDService();  
	virtual status_t onTransact(uint32_t, const Parcel&, Parcel*, uint32_t);  
};  

static int tcs_transact_binder(struct tcsd_thread_data *hte, const Parcel& data,   
                                   Parcel* reply){
	int recv_size = data.dataSize();
	int package_size;
	UINT64 offset;
	int send_package_size;

	TSS_RESULT result;
	while(recv_size>0){
		data.read(&package_size,sizeof(package_size));
		package_size = Decode_UINT32((BYTE*)&package_size);
		printf("tcs_transact_binder:Packet  size (%d bytes)", package_size);
		if (recv_size < package_size){
			printf("Packet to receive size (%d bytes) bigger than remain size(%d bytes)",
				package_size, recv_size);
			break;
		}
		if (package_size < (int)sizeof(struct tcsd_packet_hdr)) {
			printf("Packet to receive  is too small (%d bytes)",package_size);
			break;
		}
		if (package_size > hte->comm.buf_size) {
			BYTE *new_buffer;
			printf("Increasing communication buffer to %d bytes.", package_size);
			new_buffer = (BYTE *)realloc(hte->comm.buf, package_size);
			if (new_buffer == NULL) {
				LogError("realloc of %d bytes failed.", package_size);
				break;
			}
			hte->comm.buf_size = package_size;
			hte->comm.buf = new_buffer;
		}
		UINT32ToArray(package_size, hte->comm.buf);
		data.read(hte->comm.buf+sizeof(package_size),package_size-sizeof(package_size));
				/* create a platform version of the tcsd header */
#ifdef DEBUG
		printf("recv data:\n");
		player_print_hex(hte->comm.buf, package_size);
#endif
		offset = 0;
		UnloadBlob_UINT32(&offset, &hte->comm.hdr.packet_size, hte->comm.buf);
		UnloadBlob_UINT32(&offset, &hte->comm.hdr.u.result, hte->comm.buf);
		UnloadBlob_UINT32(&offset, &hte->comm.hdr.num_parms, hte->comm.buf);
		UnloadBlob_UINT32(&offset, &hte->comm.hdr.type_size, hte->comm.buf);
		UnloadBlob_UINT32(&offset, &hte->comm.hdr.type_offset, hte->comm.buf);
		UnloadBlob_UINT32(&offset, &hte->comm.hdr.parm_size, hte->comm.buf);
		UnloadBlob_UINT32(&offset, &hte->comm.hdr.parm_offset, hte->comm.buf);
#ifdef DEBUG
		printf("recv data packet_size :%d bytes, result:%d.", hte->comm.hdr.packet_size, hte->comm.hdr.u.result);
		printf("recv data num_parms :%d bytes, num_parms addr:%p\n.", hte->comm.hdr.num_parms, &(hte->comm.hdr.num_parms));
		printf("hte addr:%p,hte->comm addr:%p, hte->comm.hdr addr :%p, package size addr :%p, num_parms addr:%p\n",hte, &(hte->comm), &(hte->comm.hdr), &(hte->comm.hdr.packet_size), &(hte->comm.hdr.num_parms));
		printf("\n comm size:%d, hdr size:%d\n", sizeof(hte->comm),  sizeof(hte->comm.hdr));
#endif
		if ((result = getTCSDPacket(hte)) != TSS_SUCCESS) {
			/* something internal to the TCSD went wrong in preparing the packet
			 * to return to the TSP.  Use our already allocated buffer to return a
			 * TSS_E_INTERNAL_ERROR return code to the TSP. In the non-error path,
			 * these LoadBlob's are done in getTCSDPacket().
			 */
			/* set everything to zero, fill in what is non-zero */
			memset(hte->comm.buf, 0, hte->comm.buf_size);
			offset = 0;
			/* load packet size */
			LoadBlob_UINT32(&offset, sizeof(struct tcsd_packet_hdr), hte->comm.buf);
			/* load result */
			LoadBlob_UINT32(&offset, result, hte->comm.buf);
		}
		send_package_size = Decode_UINT32(hte->comm.buf);
#ifdef DEBUG
		printf("Sending 0x%X bytes back", send_package_size);
		printf("send data:\n");
		player_print_hex(hte->comm.buf, send_package_size);
#endif
		reply->write(hte->comm.buf, send_package_size);
		recv_size -=package_size;
	}
	return 0;
}


TCSDService::~TCSDService() {  
	free(tcsddata->comm.buf);
	tcsddata->comm.buf = NULL;
	tcsddata->comm.buf_size = -1;
	/* If the connection was not shut down cleanly, free TCS resources here */
	if (tcsddata->context != NULL_TCS_HANDLE) {
		TCS_CloseContext_Internal(tcsddata->context);
		tcsddata->context = NULL_TCS_HANDLE;
	}
	if(tcsddata->hostname != NULL) {
		free(tcsddata->hostname);
		tcsddata->hostname = NULL;
	}
}  

status_t TCSDService::onTransact(uint32_t code,   
                               const Parcel& data,   
                               Parcel* reply,  
                               uint32_t flags)  
{  
    switch(code)  
    {  
    case 0:   
        {  
	   printf("server:remote pid:%d",getCallingPid());  
	   printf("server:remote uid:%d",getCallingUid());  
	   setCallingID(getCallingPid(), getCallingUid());
	   tcs_transact_binder(tcsddata, data, reply);
            return NO_ERROR;  
        } break;  
    default:  
        return BBinder::onTransact(code, data, reply, flags);  
    }  
}  



void binder_run(struct tcsd_thread_data *data){
	sp<ProcessState> proc(ProcessState::self());
	sp<IServiceManager> sm = defaultServiceManager();
	//LOGI("ServiceManager: %p\n", sm.get());
	printf("server - serviceManager: %p\n", sm.get());
	int ret =TCSDService::Instance(data);
	printf("server - TCSDService::Instance return %d\n", ret);
	ProcessState::self()->startThreadPool();
	IPCThreadState::self()->joinThreadPool();
}

#endif
