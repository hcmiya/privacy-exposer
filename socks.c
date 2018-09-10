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

#include "privacy-exposer.h"
#include "global.h"

#ifdef NDEBUG
static int const timeout_greet = 3000;
static int const timeout_read_short = 1000;
static int const timeout_read_upstream = 20000;
static int const timeout_write = 500;
#else
static int const timeout_greet = -1;
static int const timeout_read_short = -1;
static int const timeout_read_upstream = -1;
static int const timeout_write = -1;
#endif

static void fail(int type) {
	// type
	// -1 ブツ切り
	// 0 認証情報取得中
	// >0 その値
	struct petls *tls = pthread_getspecific(sock_cleaner);
	int src = tls->src;
	char buf[] = "\x5\xff\x0\x3\x07-error-\x0\x0";
	switch(type) {
	case -1:
		break;
	case 0:
		send(src, buf, 2, MSG_NOSIGNAL);
		break;
	default:
		buf[1] = type;
		send(src, buf, 14, MSG_NOSIGNAL);
		break;
	}
	pthread_exit(NULL);
}

static void read_header(int fd, void *buf_, size_t left, int timeout, bool atgreet) {
	uint8_t *buf = buf_;
	char const * const errorat = atgreet ? "greet" : "request";
	struct pollfd po = {
		.fd = fd,
		.events = POLLIN,
	};
	while (left) {
		int poll_ret = poll(&po, 1, timeout);
		if (poll_ret == 0) {
			pelog_th(LOG_INFO, "%s: recv() timed out", errorat);
			fail(atgreet ? -1 : 3);
		}
		if (po.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			pelog_th(LOG_INFO, "%s: recv() error (by poll)", errorat);
			fail(atgreet ? -1 : 5);
		}
		ssize_t readlen = recv(fd, buf, left, 0);
		if (readlen < 0) {
			pelog_th(LOG_INFO, "%s: recv(): %s", errorat, strerror(errno));
			fail(atgreet ? -1 : 5);
		}
		if (readlen == 0) { //EOF
			pelog_th(LOG_INFO, "%s: unexpected eof", errorat);
			fail(atgreet ? -1 : 5);
		}
		left -= readlen;
		buf += readlen;
	}
}

static void write_header(int fd, void const *buf_, size_t left) {
	uint8_t const *buf = buf_;
	struct pollfd po = {
		.fd = fd,
		.events = POLLOUT,
	};
	while (left) {
		int poll_ret = poll(&po, 1, timeout_write);
		if (poll_ret == 0) {
			pelog_th(LOG_INFO, "send() timed out");
			fail(-1);
		}
		if (po.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			pelog_th(LOG_INFO, "send() error (by poll)");
			fail(-1);
		}
		ssize_t writelen = send(fd, buf, left, MSG_NOSIGNAL);
		if (writelen < 0) {
			pelog_th(LOG_INFO, "send(): %s", strerror(errno));
			fail(-1);
		}
		left -= writelen;
		buf += writelen;
	}
}

static struct rule *match_rule(char const *host, uint16_t port) {
	struct rule *rule = rule_list;

	while (rule) {
		bool rule_matched = false;
		switch (rule->type) {
		case rule_host:
			{
				bool host_matched = false;
				if (!*rule->u.host.name) {
					host_matched = true;
				}
				else if (*rule->u.host.name == '.') {
					host_matched = end_with(host, rule->u.host.name);
				}
				else {
					host_matched = strcmp(host, rule->u.host.name) == 0;
				}
				if (host_matched) {
					uint16_t *ports = rule->u.host.ports;
					for (int i = 0; i < rule->u.host.port_num; i += 2) {
						if (port >= ports[i] && port <= ports[i + 1]) return rule;
					}
				}
			}
			break;
// 		case rule_net4:
// 			{
// 			}
// 			break;
// 		case rule_net6:
// 			{
// 			}
// 			break;
		}
		rule = rule->next;
	}
	return NULL;
}

static void greet_next_proxy(struct petls *tls, char const *host, char const *port, struct proxy *proxy, int upstream) {
	while (proxy) {
		char const *nexthost, *nextport;
		uint8_t buf[300];
		if (proxy->next) {
			nexthost = proxy->next->u.host_port.name;
			nextport = proxy->next->u.host_port.port;
		}
		else {
			nexthost = host;
			nextport = port;
		}

		if (strlen(nexthost) > 255) {
			pelog_th(LOG_INFO, "upstream: too long hostname: %s", nexthost);
			fail(1);
		}
		// socks5
		pelog_th(LOG_DEBUG, "upstream: connect request");
		write_header(upstream, "\x5\x1\x0", 3);
		read_header(upstream, buf, 2, timeout_read_short, false);
		if (buf[0] != 5 || buf[1] != 0) {
			fail(5);
		}

		pelog_th(LOG_DEBUG, "upstream: tell destination");
		uint8_t *p = buf, *req = buf, hostlen = (uint8_t)strlen(nexthost);
		uint16_t portbin = htons((uint16_t)atoi(nextport));
		memcpy(p, "\x5\x1\x0\x3", 4);
		memcpy(p += 4, &hostlen, 1);
		memcpy(p += 1, nexthost, hostlen);
		memcpy(p += hostlen, &portbin, 2);
		p += 2;
		size_t reqlen = p - buf;
		write_header(upstream, req, reqlen);

		read_header(upstream, p, 5, timeout_read_upstream, false);
		if (p[0] != 5 || p[2] != 0) {
			fail(1);
		}
		int left;
		switch(p[3]) {
		case 1:
			left = 5; break;
		case 3:
			left = p[4] + 2; break;
		case 4:
			left = 17; break;
		default:
			fail(1);
		}
		read_header(upstream, p + 5, left, timeout_read_short, false);

		if (p[1]) {
			req[1] = p[1];
			write_header(tls->src, req, reqlen);
			fail(-1);
		}
		pelog_th(LOG_DEBUG, "upstream: connect succeeded");
		proxy = proxy->next;
	}
}

static int get_upstream_socket(struct petls *tls, char const *host, char const *port, struct proxy *proxy) {
	char const *nexthost, *nextport;
	bool unixsock = false;
	if (proxy) {
//		switch (proxy->type) {
// 		case proxy_type_unix_socks5:
//			unixsock = true;
// 			break;
//		}
		if (!unixsock) {
			nexthost = proxy->u.host_port.name;
			nextport = proxy->u.host_port.port;
		}
	}
	else {
		nexthost = host;
		nextport = port;
	}

	int sockfd;
	if (unixsock) {}
	else {
		struct addrinfo *res;
		int gai_ret = getaddrinfo(nexthost, nextport, &(struct addrinfo) {
			.ai_flags = AI_NUMERICSERV,
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = 6,
		}, &res);
		if (gai_ret) {
			pelog_th(LOG_INFO, "upstream: getaddrinfo(): %s", gai_strerror(gai_ret));
			fail(3);
		}
		int error = 1;
		struct addrinfo *rp;
		for (rp = res; rp; rp = rp->ai_next) {
			sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (sockfd != -1) {
				if (!connect(sockfd, rp->ai_addr, rp->ai_addrlen)) {
					break;
				}
				switch (errno) {
				case ENETUNREACH:
					error = 3; break;
				case EHOSTUNREACH:
				case ETIMEDOUT:
					error = 4; break;
				case ECONNREFUSED:
					error = 5; break;
				default:
					error = 1; break;
				}
				pelog_th(LOG_INFO, "upstream: connect(): %s", strerror(errno));
			}
			else {
				pelog_th(LOG_INFO, "upstream: socket(): %s", strerror(errno));
			}
			close(sockfd);
		}
		freeaddrinfo(res);
		if (!rp) fail(error);
	}

	tls->dest = sockfd;
	if (proxy) greet_next_proxy(tls, host, port, proxy, sockfd);
	return sockfd;
}

static int parse_header(struct petls *tls) {
	uint8_t buf[768];
	int src = tls->src;

	read_header(src, buf, 2, timeout_greet, true);
	// [0]: プロトコルバージョン
	if (buf[0] != 5) {
		fail(-1);
	}

	// 認証の種類
	int authnum = buf[1];
	read_header(src, buf, authnum, timeout_greet, true);
	int i;
	for (i = 0; i < authnum; i++) {
		if (buf[i] == 0) break;
	}
	if (i == authnum) {
		// 「認証無し」が含まれていなかった
		fail(0);
	}

	// 「認証無し」の接続を受け付けた
	write_header(src, "\x5\x0", 2);

	// 接続先要求の情報を得る
	read_header(src, buf, 4, timeout_read_short, true);
	// [0] プロトコルバージョン(5固定) [1] コマンド [2] 0固定 [3] アドレス種類
	if (buf[0] != 5 || buf[2] != 0) {
		fail(1);
	}
	if (buf[1] != 1) {
		// connect(tcp)でない
		fail(7);
	}

	// 接続先ホスト
	char destname[256], destport[6];
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
			fail(1);
		}
		read_header(src, destname, destbin[1], timeout_read_short, false);
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
	for (char *p = destname; *p; p++) *p = tolower(*p);

	// ポート
	uint8_t portbin[2];
	read_header(src, portbin, 2, timeout_read_short, false);
	uint16_t port = htons(*(uint16_t*)portbin);
	memcpy(destbin + destlen, portbin, 2);
	destlen += 2;
	sprintf(destport, "%d", port);
	sprintf(tls->reqhost, "%s#%s", destname, destport);
	pelog_th(LOG_DEBUG, "header parsed");

	// 宛先に応じたプロクシを選択
	struct rule *rule = match_rule(destname, port);
	if (rule && rule->proxy && rule->proxy->type == proxy_type_deny) {
		pelog_th(LOG_INFO, "refused by rules");
		uint8_t *p = buf;
		memcpy(p, "\x5\x2\x0", 3);
		memcpy(p += 3, destbin, destlen);
		write_header(src, buf, p - buf + destlen);
		fail(-1);
	}

	// 上流に接続してソケットを得る
	int upstream = get_upstream_socket(tls, destname, destport, rule->proxy);

	// 成功したのでこのデーモンから出ているソースアドレスとポートを接続元へ返す
	char srcname[64];
	uint8_t srcaddrbin[16];
	uint16_t srcport;
	int type = retrieve_sock_info(false, upstream, srcname, srcaddrbin, &srcport);
	size_t addrlen;
	switch(type) {
	case AF_INET: type = 1; addrlen = 4; break;
	case AF_INET6: type = 4; addrlen = 16; break;
	}
	memcpy(buf, "\x5\x0\x0", 3);
	buf[3] = type;
	memcpy(&buf[4], srcaddrbin, addrlen);
	memcpy(&buf[4 + addrlen], &(uint16_t[]){htons(srcport)}, 2);
	write_header(src, buf, addrlen + 6);

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
			pelog_relay(LOG_INFO, pp->tls, "recv %s: error: %s", pp->rname, strerror(errno));
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
				pelog_relay(LOG_INFO, pp->tls, "send %s: send(): %s", pp->wname, strerror(errno));
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

	char accept_local[40], accept_remote[40];
	uint16_t port_local, port_remote;
	retrieve_sock_info(false, src, accept_local, NULL, &port_local);
	retrieve_sock_info(true, src, accept_remote, NULL, &port_remote);
	pelog(LOG_DEBUG, "%s: accept: %s#%d <- %s#%d", tls->id, accept_local, port_local, accept_remote, port_remote);

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

