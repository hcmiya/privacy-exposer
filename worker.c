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
#include <inttypes.h>
#include <sys/wait.h>
#include <search.h>
#include <syslog.h>
#include <pthread.h>
#include <poll.h>

#include "privacy-exposer.h"
#include "global.h"

static pid_t current_worker;
static pid_t *worker_list; // SIGHUPで接続が維持されているのを溜めておくやつ
static size_t worker_num = 0; // 基本的に1つ
static int pid_pipe[2];
static volatile bool need_worker;
static volatile bool need_reload;

static int pid_cmp(void const *l_, void const *r_) {
	pid_t const *l = l_, *r = r_;
	return (int)(*l - *r);
}

static void kill_worker(void) {
	if (getpid() != root_process) return;
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
				pelog(LOG_DEBUG, "add worker pid %jd to list", (intmax_t)pid);
				lsearch(&pid, worker_list, &worker_num, sizeof(pid), pid_cmp);
			}
			else {
				pid_t dead = -pid;
				pelog(LOG_DEBUG, "delete worker pid %jd from list", (intmax_t)dead);
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

static void trap_hup(int sig) {
	need_reload = true;
}

int do_accept(struct pollfd *poll_list, size_t bind_num);

int worker_loop(struct pollfd *poll_list, int bind_num) {
	root_process = getpid();
	pelog(LOG_INFO, "root process: %ld", (long)root_process);

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

	sa.sa_handler = trap_hup;
	sigaction(SIGHUP, &sa, NULL);
	
	// 終了時にワーカープロセスにもシグナルを飛ばせるようにPIDを保存しておくやつ
	pthread_t counter_th;
	pipe(pid_pipe);
	worker_list = calloc(128, sizeof(*worker_list)); // 一応大量に取っておく
	pthread_create(&counter_th, NULL, count_worker, NULL);
	atexit(kill_worker);

	need_worker = true;
	first_worker = true;
	while (1) {
		if (need_worker) {
			pid_t pid = fork();
			switch (pid) {
			case -1:
				pelog(LOG_CRIT, "fork()", strerror(errno));
				return 1;
			case 0:
				// socks.cへ
				free(worker_list);
				close(pid_pipe[1]);
				close(pid_pipe[0]);
				return do_accept(poll_list, bind_num);
			default:
				break;
			}
			current_worker = pid;
			pelog(LOG_NOTICE, "current worker: %ld", (long)pid);
			write_worker_pid(pid);
			if (first_worker) {
				// 2回目以降は子プロセスでルールを読む
				delete_rules();
			}
			first_worker = false;
			need_worker = false;
		}

		sigsuspend(&sig_waiting);
		if (need_reload) {
			// SIGHUPを受信したのでルールを再読込する。
			// ワーカーの接続は維持される
			need_worker = true;
			kill(current_worker, SIGHUP);
			pelog(LOG_NOTICE, "received SIGHUP. reloading rules");
			need_reload = false;
		}
		else if (receive_exit_signal) {
			// INT, QUIT, TERM
			int st;
			char const *msg;
			switch (receive_exit_signal) {
			case SIGINT:
				msg = "interrupted";
				st = 1;
				break;
			case SIGQUIT:
				msg = "quitting";
				st = 1;
				break;
			case SIGTERM:
				msg = "terminating";
				st = 0;
				break;
			}
			pelog(LOG_NOTICE, "%s. send workers SIGQUIT", msg);
			close(pid_pipe[1]);
			pthread_join(counter_th, NULL);
			return st;
		}
	}
	return 0;
}
