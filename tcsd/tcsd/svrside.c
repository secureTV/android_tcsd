
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
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pwd.h>
#if (defined (__OpenBSD__) || defined (__FreeBSD__))
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsps.h"
#include "tcsd.h"
#include "req_mgr.h"

struct tcsd_config tcsd_options;
struct tpm_properties tpm_metrics;
static volatile int hup = 0, term = 0;
extern char *optarg;

static struct passwd rootpw = {
	"root",
	"root",
	0,
	0,
	"root",
	"root",
	"/system/bin/sh"
};

static void
tcsd_shutdown(void)
{
	/* order is important here:
	 * allow all threads to complete their current request */
	tcsd_threads_final();
	PS_close_disk_cache();
	auth_mgr_final();
	(void)req_mgr_final();
	conf_file_final(&tcsd_options);
	EVENT_LOG_final();
}

static void
tcsd_signal_term(int signal)
{
	term = 1;
}

void
tcsd_signal_hup(int signal)
{
	hup = 1;
}

static TSS_RESULT
signals_init(void)
{
	int rc;
	sigset_t sigmask;
	struct sigaction sa;

	sigemptyset(&sigmask);
	if ((rc = sigaddset(&sigmask, SIGTERM))) {
		LogError("sigaddset: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if ((rc = sigaddset(&sigmask, SIGHUP))) {
		LogError("sigaddset: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
#if 1
	if ((rc = THREAD_SET_SIGNAL_MASK(SIG_UNBLOCK, &sigmask, NULL))) {
		LogError("Setting thread signal mask: %s", strerror(rc));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
#endif
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = tcsd_signal_term;
	if ((rc = sigaction(SIGTERM, &sa, NULL))) {
		LogError("signal SIGTERM not registered: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	sa.sa_handler = tcsd_signal_hup;	
	if ((rc = sigaction(SIGHUP, &sa, NULL))) {
		LogError("signal SIGHUP not registered: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}

static TSS_RESULT
tcsd_startup(void)
{
	TSS_RESULT result;

#ifdef TSS_DEBUG
	/* Set stdout to be unbuffered to match stderr and interleave output correctly */
	setvbuf(stdout, (char *)NULL, _IONBF, 0);
#endif

	if ((result = signals_init()))
		return result;

	if ((result = conf_file_init(&tcsd_options)))/*need to change ,add by xlyu*/
		return result;

	if ((result = tcsd_threads_init())) {
		conf_file_final(&tcsd_options);
		return result;
	}

	if ((result = req_mgr_init())) {/*open tddl device*/
		conf_file_final(&tcsd_options);
		return result;
	}

	if ((result = ps_dirs_init())) {/*make sure ps dir  's  mode &user id/group id  allowed*/
		conf_file_final(&tcsd_options);
		(void)req_mgr_final();
		return result;
	}

	result = PS_init_disk_cache();/*read key blob from  system.data file into global varies key_disk_cache_head*/
	if (result != TSS_SUCCESS) {
		conf_file_final(&tcsd_options);
		(void)req_mgr_final();
		return result;
	}
	if ((result = get_tpm_metrics(&tpm_metrics))) {
		conf_file_final(&tcsd_options);
		PS_close_disk_cache();
		(void)req_mgr_final();
		return result;
	}

	/* must happen after get_tpm_metrics() */
	if ((result = auth_mgr_init())) {
		conf_file_final(&tcsd_options);
		PS_close_disk_cache();
		(void)req_mgr_final();
		return result;
	}

	result = EVENT_LOG_init();/*ima log and BIOS log operator*/
	if (result != TSS_SUCCESS) {
		auth_mgr_final();
		conf_file_final(&tcsd_options);
		PS_close_disk_cache();
		(void)req_mgr_final();
		return result;
	}

	result = owner_evict_init();
	if (result != TSS_SUCCESS) {
		auth_mgr_final();
		conf_file_final(&tcsd_options);
		PS_close_disk_cache();
		(void)req_mgr_final();
		return result;
	}

	return TSS_SUCCESS;
}


void
usage(void)
{
	fprintf(stderr, "\tusage: tcsd [-f] [-h]\n\n");
	fprintf(stderr, "\t-f|--foreground\trun in the foreground. Logging goes to stderr "
			"instead of syslog.\n");
	fprintf(stderr, "\t-e| attempts to connect to software TPMs over TCP");
	fprintf(stderr, "\t-h|--help\tdisplay this help message\n");
	fprintf(stderr, "\n");
}

static TSS_RESULT
reload_config(void)
{
	TSS_RESULT result;
	hup = 0;

	// FIXME: reload the config - work in progress
	result = TSS_SUCCESS;

	return result;
}

#ifdef NATIVE_SERVICE
extern struct tcsd_thread_mgr *tm;
int  main(int argc, char **argv)
{
	int result;
	if ((result = tcsd_startup()))
		return (int)result;

	tm->thread_data[0].sock = -1;
	tm->thread_data[0].context = NULL_TCS_HANDLE;
	tm->thread_data[0].hostname = "localhost";
	tm->thread_data[0].thread_id = THREAD_NULL;
	binder_run(&(tm->thread_data[0]));
	return 0;
}
#else
int
main(int argc, char **argv)
{
	struct sockaddr_in serv_addr, client_addr;
	TSS_RESULT result;
	int sd, newsd, c, option_index = 0;
	unsigned client_len;
	char *hostname = NULL;
	struct passwd *pwd;
	struct hostent *client_hostent = NULL;
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"foreground", 0, NULL, 'f'},
		{0, 0, 0, 0}
	};

	unsetenv("TCSD_USE_TCP_DEVICE");
	while ((c = getopt_long(argc, argv, "fhe", long_options, &option_index)) != -1) {
		switch (c) {
			case 'f':
				setenv("TCSD_FOREGROUND", "1", 1);
				break;
			case 'h':
				/* fall through */
			case 'e':
				setenv("TCSD_USE_TCP_DEVICE", "1", 1);
				break;
			default:
				usage();
				return -1;
				break;
		}
	}

	if ((result = tcsd_startup()))
		return (int)result;

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		LogError("Failed socket: %s", strerror(errno));
		return -1;
	}

	memset(&serv_addr, 0, sizeof (serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(tcsd_options.port);

	/* If no remote_ops are defined, restrict connections to localhost
	 * only at the socket. */
	if (tcsd_options.remote_ops[0] == 0)
		serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	c = 1;
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c));
	if (bind(sd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0) {
		LogError("Failed bind: %s", strerror(errno));
		return -1;
	}
#ifndef SOLARIS
	//pwd = getpwnam(TSS_USER_NAME);
	pwd = &rootpw;	
	if (pwd == NULL) {
		if (errno == 0) {
			LogError("User \"%s\" not found, please add this user"
					" manually.", TSS_USER_NAME);
		} else {
			LogError("getpwnam(%s): %s", TSS_USER_NAME, strerror(errno));
		}
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	setuid(pwd->pw_uid);
#endif
	if (listen(sd, TCSD_MAX_SOCKETS_QUEUED) < 0) {
		LogError("Failed listen: %s", strerror(errno));
		return -1;
	}
	client_len = (unsigned)sizeof(client_addr);
	
	if (getenv("TCSD_FOREGROUND") == NULL) {
		if (daemon(0, 0) == -1) {
			perror("daemon");
			tcsd_shutdown();
			return -1;
		}
	}

	LogInfo("%s: TCSD up and running.", PACKAGE_STRING);
	do {
		newsd = accept(sd, (struct sockaddr *) &client_addr, &client_len);
		if (newsd < 0) {
			if (errno == EINTR) {
				if (term)
					break;
				else if (hup) {
					if (reload_config() != TSS_SUCCESS)
						LogError("Failed reloading config");
				}
				continue;
			} else {
				LogError("Failed accept: %s", strerror(errno));
				continue;
			}
		}
		LogDebug("accepted socket %i", newsd);

		if ((client_hostent = gethostbyaddr((char *) &client_addr.sin_addr,
						    sizeof(client_addr.sin_addr),
						    AF_INET)) == NULL) {
			char buf[16];
                        uint32_t addr = htonl(client_addr.sin_addr.s_addr);

                        snprintf(buf, 16, "%d.%d.%d.%d", (addr & 0xff000000) >> 24,
                                 (addr & 0x00ff0000) >> 16, (addr & 0x0000ff00) >> 8,
                                 addr & 0x000000ff);

			LogWarn("Host name for connecting IP %s could not be resolved", buf);
			hostname = strdup(buf);
		} else {
			hostname = strdup(client_hostent->h_name);
		}

		tcsd_thread_create(newsd, hostname);
		hostname = NULL;
		if (hup) {
			if (reload_config() != TSS_SUCCESS)
				LogError("Failed reloading config");
		}
	} while (term ==0);

	/* To close correctly, we must receive a SIGTERM */
	return 0;
}

#endif

