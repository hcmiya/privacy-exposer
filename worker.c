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

#include "privacy-exposer.h"
#include "global.h"

static pid_t root_process;
static pid_t current_worker;
static pid_t worker_list[128]; // 一応大量に取っておく
static size_t worker_num = 0; // 基本的に1つ
static int pid_pipe[2] = {-1, -1};
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

static void trap_hup(int sig) {
	signal(SIGHUP, SIG_DFL);
	need_reload = true;
}

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

	atexit(kill_worker);

	need_worker = true;
	pthread_t counter_th;
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
			if (pid_pipe[0] == -1) {
				// 終了時にワーカープロセスにもシグナルを飛ばせるようにPIDを保存しておくやつ
				pipe(pid_pipe);
				pthread_create(&counter_th, NULL, count_worker, NULL);
			}
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
			pelog(LOG_NOTICE, "received SIGHUP. reloading rules");
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
			pelog(LOG_NOTICE, "%s. send workers SIGQUIT", msg);
			close(pid_pipe[1]);
			pthread_join(counter_th, NULL);
			return intr;
		}
	}
	return 0;
}
