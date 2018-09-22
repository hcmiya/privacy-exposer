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
#include <arpa/inet.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/un.h>
#include <stddef.h>
#include <inttypes.h>
#include <assert.h>

#include "privacy-exposer.h"
#include "global.h"

static int count_pipe[2];
static size_t connection_num;
static volatile bool quitting;

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
	write(count_pipe[1], (int8_t[]){-1}, 1);
}

static void fail(int st) {
	// type
	// -1 ブツ切り
	// 0 認証情報取得中
	// >0 その値
	if (st >= 0) {
		struct petls *tls = pthread_getspecific(sock_cleaner);
		tls->rtnbuf[1] = st ? st : 0xff;
		pelog_th(LOG_DEBUG, "close with error status %d", tls->rtnbuf[1]);
		send(tls->src, tls->rtnbuf, tls->rtnlen, MSG_NOSIGNAL);
	}
	else {
		pelog_th(LOG_DEBUG, "close without response");
	}
	pthread_exit(NULL);
}

void read_header(int fd, void *buf_, size_t left, int timeout, bool atgreet) {
	// timeoutはミリ秒
	uint8_t *buf = buf_;
	char const * const errorat = atgreet ? "greet" : "request";

	struct timeval origtmo, tmo = {
		.tv_sec = timeout / 1000,
		.tv_usec = (timeout % 1000) * 1000,
	};
	getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &origtmo, (socklen_t[]){sizeof(origtmo)});
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));

	while (left) {
		ssize_t readlen = recv(fd, buf, left, 0);
		if (readlen < 0) {
			if (errno == EINTR) continue;

			pelog_th(LOG_INFO, "%s: %s", errorat, strerror(errno));
			if (atgreet) {
				fail(-1);
			}
			int error;
			switch (errno) {
			case ECONNREFUSED:
				error = 5;
				break;
			default:
				error = errno == EAGAIN || errno == EWOULDBLOCK ? 4 : 1; break;
			}
			fail(error);
		}
		else if (readlen == 0) {
			pelog_th(LOG_INFO, "%s: unexpected eof", errorat);
			fail(atgreet ? -1 : 1);
		}
		left -= readlen;
		buf += readlen;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &origtmo, sizeof(origtmo));
}

void write_header(int fd, void const *buf_, size_t left) {
	uint8_t const *buf = buf_;
	while (left) {
		ssize_t writelen = send(fd, buf, left, MSG_NOSIGNAL);
		if (writelen < 0) {
			if (errno == EINTR) continue;
			pelog_th(LOG_INFO, "send(): %s", strerror(errno));
			fail(-1);
		}
		left -= writelen;
		buf += writelen;
	}
}

static int connect_timeout(int fd, struct sockaddr *sa, socklen_t len, int timeout_ms) {
	struct timeval tmo = {
		.tv_sec = timeout_ms / 1000,
		.tv_usec = (timeout_ms % 1000) * 1000,
	};
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tmo, sizeof(tmo));

	int error = 0;
	if (connect(fd, sa, len)) {
		switch (errno) {
		case ENETUNREACH:
			error = -3; break;
		case EINPROGRESS:
		case EHOSTUNREACH:
		case ETIMEDOUT:
			error = -4; break;
		case ECONNREFUSED:
			error = -5; break;
		default:
			error = -1; break;
		}
		pelog_th(LOG_INFO, "upstream: connect(): %s", strerror(errno));
	}
	tmo.tv_sec = tmo.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tmo, sizeof(tmo));
	return error;
}

static int connect_next(struct petls *tls, char const *host, char const *port, struct rule *rule, bool do_rec) {
	assert(rule);
	pelog_th(LOG_DEBUG, "apply rule #%zd for %s", rule->idx, host);

	bool host_is_ipaddr = false;
	switch (rule->type) {
	case rule_net4:
	case rule_net4_resolve:
	case rule_net6:
	case rule_net6_resolve:
		host_is_ipaddr = true;
		break;
	}
	struct proxy *proxy = rule->proxy;
	// 名前解決が必要で、上流でプロクシを使わない場合のみ net?-resolve マッチを行う
	bool test_net = do_rec && !host_is_ipaddr && !proxy;

	if (proxy) {
		switch (proxy->type) {
		case proxy_type_deny:
			pelog_th(LOG_INFO, "reject by rule set #%zd with code %d", rule->idx, proxy->u.deny_by);
			return -proxy->u.deny_by;
		case proxy_type_unix_socks5:
			{
				int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

				socklen_t len = offsetof(struct sockaddr_un, sun_path) + strlen(proxy->u.path) + 1;
				uint8_t buf[len];
				struct sockaddr_un *upath = (void*)buf;
				upath->sun_family = AF_UNIX;
				strcpy(upath->sun_path, proxy->u.path);

				if (connect(sockfd, (struct sockaddr *)upath, len)) {
					pelog_th(LOG_INFO, "upstream: connect() to unix: %s", strerror(errno));
					close(sockfd);
					return -1;
				}
				return sockfd;
			}
		default:
			host = proxy->u.host_port.name;
			port = proxy->u.host_port.port;
			break;
		}
	}

	struct addrinfo *res;
	int gai_ret = getaddrinfo(host, port, &(struct addrinfo) {
		.ai_flags = AI_NUMERICSERV,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 6,
	}, &res);
	if (gai_ret) {
		pelog_th(LOG_INFO, "upstream: getaddrinfo(): %s", gai_strerror(gai_ret));
		return -1;
	}

	// タイムアウトの時間を決めるためipv6があるかどうかを調べる
	// ipv6が壊れている場合に早めにipv4にフォールバックするため
	bool have_ipv4 = false, have_ipv6 = false;
	int timeout_ipv4 = 10000, timeout_ipv6 = 2000;
	struct addrinfo *rp;
	for (rp = res; rp; rp = rp->ai_next) {
		switch (rp->ai_family) {
		case AF_INET:
			have_ipv4 = true;
			break;
		case AF_INET6:
			have_ipv6 = true;
			break;
		}
	}
	if (have_ipv6 && !have_ipv4) {
		timeout_ipv6 = timeout_ipv4;
	}

	int fd;
	bool matched_ipv4 = false, matched_ipv6 = false;
REDO:
	for (rp = res; rp; rp = rp->ai_next) {
		char straddr[64];
		getnameinfo(rp->ai_addr, rp->ai_addrlen, straddr, 64, NULL, 0, NI_NUMERICHOST);

		if (test_net) {
			pelog_th(LOG_DEBUG, "upstream: test net: %s", straddr);
			struct rule *rule_resolve = match_net_resolve(rule->idx, rp->ai_addr);
			if (rule_resolve) {
				pelog_th(LOG_DEBUG, "upstream: %s: applying new rule set #%zd", straddr, rule_resolve->idx);
				switch (rp->ai_family) {
				case AF_INET:
					matched_ipv4 = true;
					break;
				case AF_INET6:
					matched_ipv6 = true;
					break;
				}
				fd = connect_next(tls, straddr, port, rule_resolve, false);
				if (fd >= 0) break;
			}
		}
		else {
			if (rp->ai_family == AF_INET && matched_ipv4) {
				continue;
			}
			if (rp->ai_family == AF_INET6 && matched_ipv6) {
				continue;
			}
			pelog_th(LOG_DEBUG, "upstream: creating connection: %s", straddr);

			tls->dest = fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			int err;
			if (fd != -1) {
				err = connect_timeout(fd, rp->ai_addr, rp->ai_addrlen, rp->ai_family == AF_INET ? timeout_ipv4 : timeout_ipv6);
				if (!err) {
					pelog_th(LOG_DEBUG, "upstream: got connection: %s", straddr);
					break;
				}
			}
			else {
				pelog_th(LOG_INFO, "upstream: socket(): %s", strerror(errno));
			}
			close(fd);
			tls->dest = -1;
			fd = err;
		}
	}
	if (!rp && test_net && !(matched_ipv4 && matched_ipv6)) {
		// net?-resolveによるIPアドレス検査でv4/v6のどちらかが引っ掛からなかった時はループをもう一度
		test_net = false;
		goto REDO;
	}
	freeaddrinfo(res);
	return fd;
}

int greet_next_proxy(char const *host, char const *port, struct proxy *proxy, int upstream);

static int get_upstream_socket(struct petls *tls, char const *host, char const *port, struct rule *rule) {
	return greet_next_proxy(host, port, rule->proxy, connect_next(tls, host, port, rule, true));
}

static void parse_header_socks5(struct petls *tls, char destname[static 256], uint16_t port[static 1]) {
	uint8_t buf[16];

	tls->server_type = server_type_socks5;
	*tls->rtnbuf = 5;
	tls->rtnlen = 2;
	int src = tls->src;

	// 認証の種類
	read_header(src, buf, 1, 50, true);
	int authnum = *buf;
	read_header(src, buf, authnum, 50, true);
	int i;
	for (i = 0; i < authnum; i++) {
		if (buf[i] == 0) break;
	}
	if (i == authnum) {
		// 「認証無し」が含まれていなかった
		pelog_th(LOG_INFO, "auth methods not acceptable");
		fail(0);
	}

	// 「認証無し」の接続を受け付けた
	write_header(src, "\x5\x0", 2);

	// fail()した時の返答
	memcpy(tls->rtnbuf, "\x5\x0\x0\x1", 4);
	tls->rtnlen = 10;

	// 接続先要求の情報を得る
	read_header(src, buf, 4, timeout_read_short, true);
	// [0] プロトコルバージョン(5固定) [1] コマンド [2] 0固定 [3] アドレス種類
	if (buf[0] != 5 || buf[2] != 0) {
		pelog_th(LOG_INFO, "broken socks 5 header");
		fail(1);
	}
	if (buf[1] != 1) {
		// connect(tcp)でない
		pelog_th(LOG_INFO, "not a CONNECT request");
		fail(7);
	}

	// 接続先ホスト
	uint8_t destbin[259];
	size_t destlen;
	destbin[0] = buf[3];
	switch (destbin[0]) {
	case 1: // IPv4
		read_header(src, &destbin[1], 4, timeout_read_short, false);
		inet_ntop(AF_INET, &destbin[1], destname, 256);
		destlen = 5;
		break;
	case 3: // FQDN
		read_header(src, &destbin[1], 1, timeout_read_short, false);
		if (destbin[1] == 0) {
			pelog_th(LOG_INFO, "malformed hostname received");
			fail(1);
		}
		read_header(src, destname, destbin[1], timeout_read_short, false);
		if (memchr(destname, '\0', destbin[1]) || (destname[destbin[1]] = '\0', !simple_host_check(destname))) {
			pelog_th(LOG_INFO, "malformed hostname received");
			fail(1);
		}
		destname[destbin[1]] = '\0';
		memcpy(&destbin[2], destname, destbin[1]);
		destlen = destbin[1] + 2;
		break;
	case 4: // IPv6
		read_header(src, &destbin[1], 16, timeout_read_short, false);
		inet_ntop(AF_INET6, &destbin[1], destname, 256);
		destlen = 17;
		break;
	default:
		fail(8);
		break;
	}
	// 小文字化
	downcase(destname);

	// ポート
	read_header(src, port, 2, timeout_read_short, false);
	memcpy(destbin + destlen, port, 2);
	*port = htons(*port);
	destlen += 2;
	if (return_bound_address || *destbin == 1) {
		// 以降でエラーした時用の返答。リクエストのアドレスを返す。
		// HACK: PrivoxyにIPv4以外の返答をすると死ぬので、-fがありIPv4でない時には固定のバイト列を返す。
		// cf. https://sourceforge.net/p/ijbswa/bugs/904/
		memcpy(&tls->rtnbuf[3], destbin, destlen);
		tls->rtnlen = destlen + 3;
	}
}

static void parse_header_socks4(struct petls *tls, char destname[static 256], uint16_t port[static 1]) {
	tls->server_type = server_type_socks4;
	*tls->rtnbuf = 0;
	tls->rtnlen = 8;

	uint8_t buf[8];
	int src = tls->src;
	read_header(src, buf, 8, 50, true);
	// [0]: command, [1-2]: port, [3-6]: dest, [7]: null (user id termination)
	if (buf[0] != 1) {
		pelog_th(LOG_INFO, "unsupported method");
		fail(91);
	}
	if (buf[7] != 0) {
		pelog_th(LOG_INFO, "user auth not supported");
		fail(91);
	}

	if (memcmp(&buf[3], "\x0\x0\x0", 3) == 0 && buf[6]) { // dest = 0.0.0.x
		struct timeval origtmo;
		getsockopt(src, SOL_SOCKET, SO_RCVTIMEO, &origtmo, (socklen_t[]){sizeof(origtmo)});
		setsockopt(src, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval){.tv_usec = 50000}, sizeof(origtmo)); // 50ms
		do {
			// ホスト名読み取り
			ssize_t readlen = recv(src, destname, 256, MSG_PEEK);
			if (readlen == -1) {
				if (errno == EINTR) continue;
				pelog_th(LOG_INFO, "header: recv(): %s", strerror(errno));
				fail(-1);
			}
			char *p = memchr(destname, '\0', readlen);
			if (!p) {
				// 256文字を受信する前に割り込みで止まり文字列が終端しない可能性もあるが
				// そのままエラーで死ぬ
				if (readlen == 256) {
					pelog_th(LOG_INFO, "requested hostname too long", strerror(errno));
				}
				else {
					pelog_th(LOG_INFO, "invalid socks 4 header");
				}
				fail(-1);
			}
			read_header(src, destname, p - destname + 1, 50, true);
		} while (0);
		setsockopt(src, SOL_SOCKET, SO_RCVTIMEO, &origtmo, sizeof(origtmo));
		if (!*destname || !simple_host_check(destname)) {
			pelog_th(LOG_INFO, "invalid hostname");
			fail(91);
		}
	}
	else {
		inet_ntop(AF_INET, &buf[3], destname, 256);
	}
	tls->rtnbuf[1] = 90;
	*port = htons(*(uint16_t*)&buf[1]);
}

static int parse_header(struct petls *tls) {
	uint8_t buf[768];
	char destname[256], destport[6];
	uint16_t port;
	int src = tls->src;

	// ヘッダ返信のタイムアウトは常に500ms
	setsockopt(src, SOL_SOCKET, SO_SNDTIMEO, &(struct timeval){.tv_usec = 500000}, sizeof(struct timeval));

	read_header(src, buf, 1, timeout_greet, true);
	// [0]: プロトコルバージョン
	if (*buf == 5) {
		parse_header_socks5(tls, destname, &port);
	}
	else if (*buf == 4) {
		parse_header_socks4(tls, destname, &port);
	}
	else {
		pelog_th(LOG_INFO, "not a socks request");
		fail(-1);
	}

	sprintf(destport, "%u", port);
	sprintf(tls->reqhost, "%s#%s", destname, destport);
	pelog_th(LOG_DEBUG, "header parsed");

	// 宛先に応じたプロクシを選択し、上流に接続してソケットを得る
	int upstream = get_upstream_socket(tls, destname, destport, match_rule(destname, port));
	if (upstream < 0) fail(-upstream);

	// 成功したのでこのデーモンから出ているソースアドレスとポートを接続元へ返す
	char srcname[64];
	uint8_t srcaddrbin[16];
	uint16_t srcport;
	int type = retrieve_sock_info(false, upstream, srcname, srcaddrbin, &srcport);

	if (tls->server_type == server_type_socks5 && return_bound_address) {
		size_t addrlen;
		switch(type) {
		case AF_INET: type = 1; addrlen = 4; break;
		case AF_INET6: type = 4; addrlen = 16; break;
		case AF_UNIX: type = 3; addrlen = 5; memcpy(srcaddrbin, "\x4unix", 5); break;
		}
		memcpy(buf, "\x5\x0\x0", 3);
		tls->rtnbuf[3] = type;
		memcpy(&tls->rtnbuf[4], srcaddrbin, addrlen);
		memcpy(&tls->rtnbuf[4 + addrlen], (uint16_t[]){htons(srcport)}, 2);
		tls->rtnlen = addrlen + 6;
	}
	write_header(src, tls->rtnbuf, tls->rtnlen);

	// 返信のタイムアウトを元に戻す
	setsockopt(src, SOL_SOCKET, SO_SNDTIMEO, &(struct timeval){0}, sizeof(struct timeval));

	// ログ: dest <- relay | relay <- src
	retrieve_sock_info(true, upstream, destname, srcaddrbin, &port);
	sprintf((char*)buf, "established: %s#%d <- %s#%d | ", destname, port, srcname, srcport);
	retrieve_sock_info(false, src, destname, srcaddrbin, &port);
	retrieve_sock_info(true, src, srcname, srcaddrbin, &srcport);
	sprintf((char*)buf + strlen((char*)buf), "%s#%d <- %s#%d", destname, port, srcname, srcport);

	pelog_th(LOG_INFO, "%s", buf);
	return upstream;
}

struct portpair {
	char const *rname, *wname;
	int r, w;
	struct petls *tls;
};

void pelog_relay(int pri, struct petls *tls, char const *fmt, ...) {
	char idfmt[256];
	sprintf(idfmt, "%s %s: %ldms: %s", tls->id, tls->reqhost, lapse_ms(&tls->btime), fmt);

	va_list ap;
	va_start(ap, fmt);
	vpelog(pri, idfmt, ap);
	va_end(ap);
}

void *do_relay(void *pp_) {
	struct portpair *pp = pp_;
	size_t const buflen = 2048;
	uint8_t buf[buflen];
	size_t recv_total = 0;
	size_t send_total = 0;
	struct pollfd pw = {
		.fd = pp->w,
		.events = POLLOUT,
	};

	int poll_ret;
	while (1) {
		ssize_t readlen = recv(pp->r, buf, buflen, 0);
		if (readlen == -1) {
			if (errno == EINTR) continue;
			pelog_relay(LOG_INFO, pp->tls, "recv %s: %s", pp->rname, strerror(errno));
			break;
		} else if (readlen == 0) {
			break;
		}
//		pelog_relay(LOG_DEBUG, pp->id, "recv %s: %zd", pp->rname, readlen);
		recv_total += readlen;

		uint8_t *p = buf;
		while (readlen) {
			ssize_t writelen = send(pp->w, p, readlen, MSG_NOSIGNAL);
			if (writelen == -1) {
				if (errno == EINTR) continue;
				pelog_relay(LOG_INFO, pp->tls, "send %s: %s", pp->wname, strerror(errno));
				goto CLOSE;
			}
//			pelog_relay(LOG_DEBUG, pp->id, "send %s: %zd in %zd", pp->wname, writelen, readlen);
			readlen -= writelen;
			p += writelen;
			send_total += writelen;
		}
	}
CLOSE:
	shutdown(pp->w, SHUT_WR);
	shutdown(pp->r, SHUT_RD);
	pelog_relay(LOG_DEBUG, pp->tls, "total: recv %s: %zu, send %s: %zu",
		pp->rname, recv_total, pp->wname, send_total
	);
	pelog_relay(LOG_DEBUG, pp->tls, "shutdown: %s -> %s", pp->rname, pp->wname);

	return NULL;
}

void *do_socks(void *tls_) {
	struct petls *tls = tls_;
	pthread_setspecific(sock_cleaner, tls);
	int src = tls->src;

	char accept_local[64], accept_remote[64];
	uint16_t port_local, port_remote;
	retrieve_sock_info(false, src, accept_local, NULL, &port_local);
	retrieve_sock_info(true, src, accept_remote, NULL, &port_remote);
	pelog(LOG_DEBUG, "%s: accept: %s#%d <- %s#%d", tls->id, accept_local, port_local, accept_remote, port_remote);
	sprintf(tls->reqhost, "(req from %s)", accept_remote);

	clock_gettime(CLOCK_REALTIME, &tls->btime);
	int upstream = parse_header(tls);

	pthread_t th;
	char const * const local = "local";
	char const * const remote = "remote";
	pthread_create(&th, NULL, do_relay, &(struct portpair) {
		.r = upstream, .rname = remote,
		.w = src, .wname = local,
		.tls = tls,
	});
	do_relay(&(struct portpair) {
		.r = src, .rname = local,
		.w = upstream, .wname = remote,
		.tls = tls,
	});
	pthread_join(th, NULL);
	return NULL;
}

static void force_exit(int sig) {
	exit(1);
}
static void trap_hup(int hup) {
	quitting = true;
}

static void *count_connection(void *_) {
	int8_t incr;
	ssize_t readlen;
	while ((readlen = read(count_pipe[0], &incr, 1)) != 0) {
		if (readlen > 0) {
			connection_num += incr;
			if (incr < 0) {
				pelog(LOG_DEBUG, "%zu connections left", connection_num);
			}
		}
		if (quitting && !connection_num) {
			close(count_pipe[1]);
		}
	}
}

int do_accept(struct pollfd *poll_list, size_t bind_num) {
	signal(SIGINT, SIG_DFL);

	struct sigaction sa = {0};
	sigfillset(&sa.sa_mask);
	sa.sa_handler = force_exit,
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sa.sa_handler = trap_hup;
	sigaction(SIGHUP, &sa, NULL);

	pipe(count_pipe);
	pthread_t count_th;
	pthread_create(&count_th, NULL, count_connection, NULL);

	pthread_attr_t pattr;
	pthread_attr_init(&pattr);
	pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);

	pthread_key_create(&sock_cleaner, clean_sock);

	sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL);

	if (!first_worker) load_rules();

	int thread_id = 1;
	int live = bind_num;
	while (!quitting && live) {
		int poll_ret = poll(poll_list, bind_num, -1);
		if (poll_ret < 0) {
			if (errno == EINTR) break;
			pelog(LOG_ERR, "poll(): %s", strerror(errno));
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
				pthread_create((pthread_t[]){0}, &pattr, do_socks, tls);
				write(count_pipe[1], (uint8_t[]){1}, 1);
			}
			else if (poll_list[i].revents) {
				pelog(LOG_ERR, "accept() (from poll())");
				poll_ret--;
				// FIXME: ソケットが死んだらどうしたらいい?
				poll_list[i].fd = ~poll_list[i].fd;
				live--;
			}
		}
	}
	if (quitting) {
		pelog(LOG_NOTICE, "received SIGHUP. %zu connections are retained until close", connection_num);
	}
	else if (!live) {
		pelog(LOG_NOTICE, "all sockets died?");
	}
	write(count_pipe[1], (uint8_t[]){0}, 1);
	pthread_join(count_th, NULL);
	pelog(LOG_NOTICE, "exited gracefully");
	return 0;
}
