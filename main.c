#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <sys/select.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>
#include <inttypes.h>

#define GLOBAL_MAIN
#include "privacy-exposer.h"
#include "global.h"

static char const *pidfile;

static void conf_from_env_(char const ** gvar, char const *varname) {
	char const *env = getenv(varname);
	if (env && *env) {
		*gvar = strdup(env);
	}
}

static void init(int argc, char **argv) {
#define conf_from_env(X) conf_from_env_(&X, #X);
	conf_from_env(BIND_ADDR);
	conf_from_env(BIND_PORT);
	conf_from_env(UPSTREAM_ADDR);
	conf_from_env(UPSTREAM_PORT);
#undef conf_from_env

	int c;
	long loglevel = -1;
	char *endp;
	while ((c = getopt(argc, argv, "p:l:")) != -1) {
		switch (c) {
		case 'p':
			pidfile = optarg;
			break;
		case 'l':
			errno = 0;
			loglevel = strtol(optarg, &endp, 10);
			if (endp == optarg || errno == ERANGE || loglevel < 0 || loglevel > 7) {
				fprintf(stderr, "invalid loglevel\n");
				exit(1);
			}
			break;
		case '?':
			exit(1);
			break;
		}
	}

	pelog_open(!!pidfile, loglevel != -1 ? loglevel : pidfile ? 5 : 7);
}

static void daemonize() {
	FILE *pidfp = fopen(pidfile, "w");
	if (!pidfp) {
		pelog(LOG_CRIT, "creating pidfile: %s: %s", pidfile, strerror(errno));
		exit(1);
	}

	switch (fork()) {
	case -1:
		pelog(LOG_CRIT, "daemonize: %s", strerror(errno));
		exit(1);
	case 0:
		break;
	default:
		exit(0);
	}

	setsid();
	switch (fork()) {
	case -1:
		pelog(LOG_CRIT, "daemonize: %s", strerror(errno));
		exit(1);
	case 0:
		break;
	default:
		exit(0);
	}

	fprintf(pidfp, "%d\n", getpid());
	if (fclose(pidfp)) {
		// ディスクフルとか
		pelog(LOG_CRIT, "writing pid: %s: %s", pidfile, strerror(errno));
	}
	chdir("/");
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
}

void clean_sock(void *tls_) {
	struct petls *tls = tls_;
	shutdown(tls->src, SHUT_RDWR);
	close(tls->src);
	if (tls->dest != -1) {
		shutdown(tls->dest, SHUT_RDWR);
		close(tls->dest);
	}
	pelog(LOG_DEBUG, "%s %s: %dms: clean", tls->id, tls->reqhost, lapse_ms(&tls->btime));
	free(tls);
}

void trap(int sig) {
	bool intr = sig == SIGINT;
	pelog(LOG_NOTICE, intr ? "interrupted" : "terminated");
	exit(intr);
}

int main(int argc, char **argv) {
	init(argc, argv);

	struct addrinfo *res;
	int gai_ret = getaddrinfo(BIND_ADDR, BIND_PORT, &(struct addrinfo) {
		.ai_flags = AI_PASSIVE | AI_NUMERICSERV,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 6,
	}, &res);
	if (gai_ret) {
		pelog(LOG_CRIT, "bind name error: %s", gai_strerror(gai_ret));
		return 1;
	}

	struct pollfd poll_list[16];
	int bind_num = 0;
	for (struct addrinfo *rp = res; rp && bind_num < 16; rp = rp->ai_next) {
		char addr[64];
		char txtport[6];
		getnameinfo(rp->ai_addr, rp->ai_addrlen, addr, 58, txtport, 6, NI_NUMERICHOST | NI_NUMERICSERV);
		sprintf(addr + strlen(addr), "#%s", txtport);
		poll_list[bind_num].fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (poll_list[bind_num].fd < 0) {
			pelog(LOG_ERR, "failed to create socket: %s: %s", addr, strerror(errno));
			continue;
		}

		int bind_ret = bind(poll_list[bind_num].fd, rp->ai_addr, rp->ai_addrlen);
		if (bind_ret) {
			pelog(LOG_ERR, "failed to bind: %s: %s", addr, strerror(errno));
			close(poll_list[bind_num].fd);
		}
		else {
			if (listen(poll_list[bind_num].fd, 20) < 0) {
				pelog(LOG_ERR, "failed to listen: %s: %s", addr, strerror(errno));
				close(poll_list[bind_num].fd);
			}
			else {
				poll_list[bind_num].events = POLLIN;
				poll_list[bind_num].revents = 0;
				pelog(LOG_NOTICE, "listen: %s", addr);
				bind_num++;
			}
		}
	}
	freeaddrinfo(res);
	if (!bind_num) {
		pelog(LOG_CRIT, "sockets not created");
		return 1;
	}

	if (pidfile) {
		daemonize();
		pelog(LOG_NOTICE, "daemonized. %jd", (intmax_t)getpid());
	}

	struct sigaction sa = {
		.sa_handler = trap,
	};
	sigfillset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	pthread_attr_t pattr;
	pthread_attr_init(&pattr);
	pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);

	pthread_key_create(&sock_cleaner, clean_sock);

	int thread_id = 1;
	for (int live = bind_num; live;) {
		int poll_ret = poll(poll_list, bind_num, -1);
		if (poll_ret < 0) {
			pelog(LOG_CRIT, "poll(): %s", strerror(errno));
			return 1;
		}

		for (int i = 0; i < bind_num && poll_ret; i++) {
			if (poll_list[i].revents & POLLIN) {
				poll_ret--;
				int confd = accept(poll_list[i].fd, NULL, NULL);
				if (confd < 0) {
					pelog(LOG_ERR, "accept(): %s", strerror(errno));
					continue;
				}
				struct petls *tls = calloc(1, sizeof(*tls));
				tls->src = confd;
				tls->dest = -1;
				sprintf(tls->id, "%08"PRIX32, thread_id++);
				strcpy(tls->reqhost, "(?)");
				pthread_create((pthread_t[]){0}, &pattr, do_socks, tls);
			}
			else if (poll_list[i].revents) {
				pelog(LOG_ERR, "accept() (from poll())");
				poll_ret--;
				poll_list[i].fd = ~poll_list[i].fd;
				live--;
			}
		}
	}

	pelog(LOG_CRIT, "no listening sockets. aborted");
	return 1;
}
