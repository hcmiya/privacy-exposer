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
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <inttypes.h>
#include <sys/wait.h>

#define GLOBAL_MAIN
#include "privacy-exposer.h"
#include "global.h"

static char const *pidfile;

static int init(int argc, char **argv) {
	int c;
	long loglevel = -1;
	char *endp;
	bool check_rule_only = false;

	while ((c = getopt(argc, argv, "cfl:p:r:")) != -1) {
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
		case 'r':
			rule_file_path = optarg;
			break;
		case 'f':
			return_bound_address = false;
			break;
		case 'c':
			check_rule_only = true;
			break;
		case '?':
			exit(1);
			break;
		}
	}

	if (pidfile && *rule_file_path != '/') {
		fprintf(stderr, "rules file must be specified by full path in daemon mode\n");
		exit(1);
	}
	if (check_rule_only) {
		loglevel = 2;
	}

	pelog_open(!!pidfile && !check_rule_only, loglevel != -1 ? loglevel : pidfile ? 5 : 7);
	load_rules();
	if (check_rule_only) exit(0);

	return optind;
}

struct pollfd *do_listen(char **argv, int *bind_num_ret) {
	struct pollfd *poll_list = NULL;
	int bind_num = 0;
	while (*argv) {
		char const *bind_addr = *argv++;
		if (!*argv) {
			pelog(LOG_WARNING, "lacks binding port for %s. skipping", bind_addr);
			break;
		}
		char const *bind_port = *argv++;

		struct addrinfo *res;
		int gai_ret = getaddrinfo(bind_addr, bind_port, &(struct addrinfo) {
			.ai_flags = AI_PASSIVE | AI_NUMERICSERV,
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = 6,
		}, &res);
		if (gai_ret) {
			pelog(LOG_CRIT, "%s: bind name error: %s", bind_addr, gai_strerror(gai_ret));
			continue;
		}

		for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
			char addr[64];
			char txtport[6];
			getnameinfo(rp->ai_addr, rp->ai_addrlen, addr, 58, txtport, 6, NI_NUMERICHOST | NI_NUMERICSERV);
			sprintf(addr + strlen(addr), "#%s", txtport);
			int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (fd < 0) {
				pelog(LOG_ERR, "failed to create socket: %s: %s", addr, strerror(errno));
				continue;
			}
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int));

			int bind_ret = bind(fd, rp->ai_addr, rp->ai_addrlen);
			if (bind_ret) {
				pelog(LOG_ERR, "failed to bind: %s: %s", addr, strerror(errno));
				close(fd);
			}
			else {
				if (listen(fd, 10) < 0) {
					pelog(LOG_ERR, "failed to listen: %s: %s", addr, strerror(errno));
					close(fd);
				}
				else {
					if (bind_num % 8 == 0) {
						struct pollfd *tmp = realloc(poll_list, sizeof(*poll_list) * (bind_num + 8));
						poll_list = tmp;
					}
					poll_list[bind_num].fd = fd;
					poll_list[bind_num].events = POLLIN;
					pelog(LOG_NOTICE, "listen: %s", addr);
					bind_num++;
				}
			}
		}
		freeaddrinfo(res);
	}
	if (!bind_num) {
		pelog(LOG_CRIT, "sockets not created. quitting");
		return NULL;
	}
	*bind_num_ret = bind_num;
	return poll_list;
}

static void daemonize() {
	FILE *pidfp = fopen(pidfile, "w");
	if (!pidfp) {
		pelog(LOG_CRIT, "creating pidfile: %s: %s", pidfile, strerror(errno));
		exit(1);
	}

	int pp[2];
	pipe(pp);
	pid_t daemonpid;
	switch (fork()) {
	case -1:
		pelog(LOG_CRIT, "daemonize: %s", strerror(errno));
		exit(1);
	case 0:
		close(pp[0]);
		break;
	default:
		close(pp[1]);
		ssize_t readlen = read(pp[0], &daemonpid, sizeof(daemonpid));
		if (readlen <= 0) {
			exit(1);
		}
		close(pp[0]);
		fprintf(pidfp, "%ld\n", (long)daemonpid);
		if (fclose(pidfp)) {
			// ディスクフルとか
			kill(daemonpid, SIGKILL);
			pelog(LOG_CRIT, "writing pid: %s: %s", pidfile, strerror(errno));
			exit(1);
		}
		fprintf(stderr, "privacy-exposer: daemonized. %ld\n", (long)daemonpid);
		_exit(0);
	}

	setsid();
	switch (fork()) {
	case -1:
		pelog(LOG_CRIT, "daemonize: %s", strerror(errno));
		close(pp[1]);
		_exit(1);
	case 0:
		break;
	default:
		_exit(0);
	}

	daemonpid = getpid();
	write(pp[1], &daemonpid, sizeof(daemonpid));
	close(pp[1]);

	chdir("/");
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
}

int worker_loop(struct pollfd *poll_list, int bind_num);

int main(int argc, char **argv) {
	int argstart = init(argc, argv);
	argc -= argstart;
	argv += argstart;

	char *args_default[] = { "localhost", "9000", NULL };
	if (argc < 2) {
		if (argc == 1) args_default[0] = *argv;
		argv = args_default;
	}

	int bind_num;
	struct pollfd *poll_list = do_listen(argv, &bind_num);
	if (!poll_list) return 1;

	if (pidfile) {
		daemonize();
	}
	// worker.cへ
	return worker_loop(poll_list, bind_num);
}
