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
#include <pthread.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <search.h>


#define GLOBAL_MAIN
#include "privacy-exposer.h"
#include "global.h"

static char const *pidfile;

static int init(int argc, char **argv) {
	int c;
	long loglevel = -1;
	char *endp;
	while ((c = getopt(argc, argv, "p:l:r:")) != -1) {
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
			rule_path = optarg;
			break;
		case '?':
			exit(1);
			break;
		}
	}

	if (pidfile && rule_path && *rule_path != '/') {
		fprintf(stderr, "rules file must be specified by full path in daemon mode\n");
		exit(1);
	}

	pelog_open(!!pidfile, loglevel != -1 ? loglevel : pidfile ? 5 : 7);
	load_rules();

	return optind;
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

// シグナル処理・プロセス保存関連

static pid_t current_worker;
static pid_t worker_list[16];
static size_t worker_num = 0; // 基本的に1つ
static int pid_pipe[2];
static volatile bool need_worker;
static volatile bool need_reload;

static int pid_cmp(void const *l_, void const *r_) {
	pid_t const *l = l_, *r = r_;
	return (int)(*l - *r);
}

static void kill_worker(void) {
	for (int i = 0; i < worker_num; i++) {
		kill(worker_list[i], SIGQUIT);
	}
}

static void *count_worker(void *_) {
	pid_t pid;
	ssize_t readlen;
	while (readlen = read(pid_pipe[0], &pid, sizeof(pid))) {
		if (readlen > 0) {
			if (pid > 0) {
				lsearch(&pid, worker_list, &worker_num, sizeof(pid), pid_cmp);
			}
			else {
				pid_t dead = -pid;
				pid_t *p = lfind(&dead, worker_list, &worker_num, sizeof(dead), pid_cmp);
				memmove(p, p + 1, (--worker_num - (p - worker_list)) * sizeof(*p));
				if (!worker_num && !need_worker) {
					// ワーカーが不意に死んだ?
					pelog(LOG_CRIT, "all workers died unexpectedly. quitting");
					exit(1);
				}
			}
		}
	}
}
static void write_worker_pid(pid_t pid) {
	write(pid_pipe[1], &pid, sizeof(pid));
}

static volatile int receive_exit_signal;
static void trap_exit(int sig) {
	receive_exit_signal = sig;
}

static void trap_child(int sig) {
	pid_t dead;
	while ((dead = waitpid(-1, (int[]){0}, WNOHANG)) > 0) {
		write_worker_pid(-dead);
	}
}

void trap_hup(int sig) {
	signal(SIGHUP, SIG_DFL);
	need_reload = true;
}

// シグナル処理・プロセス保存関連ここまで

int main(int argc, char **argv) {
	int argstart = init(argc, argv);
	char *bind_addr, *bind_port;
	if (argv[argstart]) {
		bind_addr = argv[argstart];
		bind_port = argv[argstart + 1] ? argv[argstart + 1] : "9000";
	}
	else {
		bind_addr = "localhost";
		bind_port = "9000";
	}

	struct addrinfo *res;
	int gai_ret = getaddrinfo(bind_addr, bind_port, &(struct addrinfo) {
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
				setsockopt(poll_list[bind_num].fd, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int));
				poll_list[bind_num].events = POLLIN;
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
	}
	pelog(LOG_INFO, "root process: %ld", (long)getpid());

	// ここからシグナルを全部ブロックしておいて、fork()した後でsigsuspend()する
	sigset_t sig_block_all, sig_waiting;
	sigfillset(&sig_block_all);
	sigprocmask(SIG_BLOCK, &sig_block_all, &sig_waiting);

	struct sigaction sa = {0};
	sigfillset(&sa.sa_mask);
	sa.sa_handler = trap_child;
	sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = trap_exit;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	// 終了時にワーカープロセスにもシグナルを飛ばせるようにPIDを保存しておくやつ
	pipe(pid_pipe);
	pthread_t counter_th;
	pthread_create(&counter_th, NULL, count_worker, NULL);

	atexit(kill_worker);

	need_worker = true;
	while (1) {
		if (need_worker) {
			pid_t pid = fork();
			switch (pid) {
			case -1:
				pelog(LOG_CRIT, "fork()", strerror(errno));
				return 1;
			case 0:
				// socks.cへ
				return do_accept(poll_list, bind_num);
			default:
				break;
			}
			current_worker = pid;
			pelog(LOG_NOTICE, "current worker: %ld", (long)pid);
			write_worker_pid(pid);
			need_worker = false;
			sa.sa_handler = trap_hup;
			sigaction(SIGHUP, &sa, NULL);
		}

		sigsuspend(&sig_waiting);
		if (need_reload) {
			// SIGHUPを受信したのでルールを再読込する。
			// ワーカーの接続は維持される
			need_worker = true;
			kill(current_worker, SIGHUP);
			pelog(LOG_NOTICE, "reloading rules");
			delete_rules();
			load_rules();
			need_reload = false;
		}
		else if (receive_exit_signal) {
			// INT, QUIT, TERM
			bool intr = receive_exit_signal == SIGINT;
			char const *msg;
			switch (receive_exit_signal) {
			case SIGINT:
				msg = "interrupted";
				break;
			case SIGQUIT:
				msg = "quitting";
				break;
			case SIGTERM:
				msg = "terminating";
				break;
			}
			pelog(LOG_NOTICE, "%s. send workers quit signal", msg);
			close(pid_pipe[1]);
			pthread_join(counter_th, NULL);
			return intr;
		}
	}
	return 0;
}
