#ifdef NATIVE_SERVICE
#ifndef _SVRSIDE_BINDER_H_
#define _SVRSIDE_BINDER_H_
#ifdef __cplusplus
extern "C"{
#endif
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_int_literals.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tcslog.h"
#include "rpc_tcstp_tcs.h"


void binder_run(struct tcsd_thread_data *data);
#ifdef __cplusplus
}
#endif

#endif
#endif



