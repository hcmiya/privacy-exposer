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

#include "privacy-exposer.h"
#include "global.h"

static int const timeout_short = 3000;

static void exit_shutdown(int onerror) {
	// onerror
	// -1 ブツ切り
	// 0 認証情報取得中
	// >0 その値
	int *sockpair = pthread_getspecific(sock_cleaner);
	int src = sockpair[0];
	char buf[] = "\x5\xff\x0\x3\x07-error-\x0\x0";
	switch(onerror) {
	case -1:
		break;
	case 0:
		send(src, buf, 2, MSG_NOSIGNAL);
		break;
	default:
		buf[1] = onerror;
		send(src, buf, 14, MSG_NOSIGNAL);
		break;
	}
	pthread_exit(NULL);
}

static void read_data(int fd, void *buf_, size_t left, int timeout, bool athead) {
	uint8_t *buf = buf_;
	struct pollfd po = {
		.fd = fd,
		.events = POLLIN,
	};
	while (left) {
		int poll_ret = poll(&po, 1, timeout);
		if (poll_ret == 0) {
			pelog(LOG_NOTICE, "timed out on recv");
			exit_shutdown(athead ? -1 : 3);
		}
		if (po.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			pelog(LOG_NOTICE, "error on recv (by poll)");
			exit_shutdown(athead ? -1 : 5);
		}
		ssize_t readlen = recv(fd, buf, left, 0);
		if (readlen < 0) {
			pelog(LOG_NOTICE, "error on recv: %s", strerror(errno));
			exit_shutdown(athead ? -1 : 5);
		}
		if (readlen == 0) { //EOF
			pelog(LOG_NOTICE, "unexpected eof");
			exit_shutdown(athead ? -1 : 5);
		}
		left -= readlen;
		buf += readlen;
	}
}

static void write_data(int fd, void const *buf_, size_t left) {
	uint8_t const *buf = buf_;
	struct pollfd po = {
		.fd = fd,
		.events = POLLOUT,
	};
	while (left) {
		int poll_ret = poll(&po, 1, 2000);
		if (poll_ret == 0) {
			pelog(LOG_NOTICE, "timed out on send");
			exit_shutdown(-1);
		}
		if (po.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			pelog(LOG_NOTICE, "error on send (by poll)");
			exit_shutdown(-1);
		}
		ssize_t writelen = send(fd, buf, left, MSG_NOSIGNAL);
		if (writelen < 0) {
			pelog(LOG_NOTICE, "error on send: %s", strerror(errno));
			exit_shutdown(-1);
		}
		left -= writelen;
		buf += writelen;
	}
}

static bool end_with(char const *haystack, char const *needle) {
	size_t hlen = strlen(haystack);
	size_t nlen = strlen(needle);
	return hlen >= nlen && !strcmp(haystack + hlen - nlen, needle);
}

static int get_upstream_socket(char const *host, char const *port) {
	struct addrinfo *res;
	int gai_ret = getaddrinfo(host, port, &(struct addrinfo) {
		.ai_flags = AI_NUMERICSERV,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 6,
	}, &res);
	if (gai_ret) {
		pelog(LOG_NOTICE, "upstream: name resolution failed: %s", gai_strerror(gai_ret));
		exit_shutdown(3);
	}
	int error = 1;
	for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
		int sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd != -1) {
			int conerr = connect(sockfd, rp->ai_addr, rp->ai_addrlen);
			if (!conerr) {
				int *sockpair = pthread_getspecific(sock_cleaner);
				sockpair[1] = sockfd;
				freeaddrinfo(res);
				return sockfd;
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
			pelog(LOG_NOTICE, "upstream: connect() error: %s", strerror(errno));
		}
		else {
			pelog(LOG_NOTICE, "upstream: socket() error: %s", strerror(errno));
		}
		close(sockfd);
	}
	freeaddrinfo(res);
	exit_shutdown(error);
	// NOTREACHED
}

static int parse_header(int src) {
	uint8_t buf[768];

	read_data(src, buf, 2, timeout_short, true);
	// [0]: プロトコルバージョン
	if (buf[0] != 5) {
		exit_shutdown(-1);
	}

	// 認証の種類
	int authnum = buf[1];
	read_data(src, buf, authnum, timeout_short, true);
	int i;
	for (i = 0; i < authnum; i++) {
		if (buf[i] == 0) break;
	}
	if (i == authnum) {
		// 「認証無し」が含まれていなかった
		exit_shutdown(0);
	}

	// 「認証無し」の接続を受け付けた
	write_data(src, "\x5\x0", 2);

	// 接続先要求の情報を得る
	read_data(src, buf, 4, timeout_short, true);
	// [0] プロトコルバージョン(5固定) [1] コマンド [2] 0固定 [3] アドレス種類
	if (buf[0] != 5 || buf[2] != 0) {
		exit_shutdown(1);
	}
	if (buf[1] != 1) {
		// connect(tcp)でない
		exit_shutdown(7);
	}

	// 接続先ホスト
	char destname[262], *destport;
	uint8_t destbin[257];
	size_t destlen;
	destbin[0] = buf[3];
	switch (destbin[0]) {
	case 1: // IPv4
		read_data(src, &destbin[1], 4, timeout_short, false);
		inet_ntop(AF_INET, &destbin[1], destname, 262);
		destlen = 5;
		break;
	case 3: // FQDN
		read_data(src, &destbin[1], 1, timeout_short, false);
		if (destbin[1] == 0) {
			exit_shutdown(1);
		}
		read_data(src, destname, destbin[1], timeout_short, false);
		destname[destbin[1]] = '\0';
		memcpy(&destbin[2], destname, destbin[1]);
		destlen = destbin[1] + 2;
		break;
	case 4: // IPv6
		read_data(src, &destbin[1], 16, timeout_short, false);
		inet_ntop(AF_INET6, &destbin[1], destname, 262);
		destlen = 17;
		break;
	default:
		exit_shutdown(8);
		break;
	}

	// ポート
	destport = destname + strlen(destname) + 1;
	uint8_t portbin[2];
	read_data(src, portbin, 2, timeout_short, false);
	uint16_t port = htons(*(uint16_t*)portbin);
	sprintf(destport, "%d", port);
	if (port != 80 && port != 443) {
		exit_shutdown(2);
	}

	pelog(LOG_INFO, "request: %s#%d", destname, port);

	// 上流に接続してソケットを得る
	bool to_dark = end_with(destname, ".onion") || end_with(destname, ".i2p");
	int upstream;
	if (to_dark) {
		upstream = get_upstream_socket(UPSTREAM_ADDR, UPSTREAM_PORT);
	}
	else {
		upstream = get_upstream_socket(destname, destport);
	}

	if (to_dark) {
		// socks
		pelog(LOG_DEBUG, "upstream: connect request");
		write_data(upstream, "\x5\x1\x0", 3);
		read_data(upstream, buf, 2, timeout_short, false);
		if (buf[0] != 5 || buf[1] != 0) {
			exit_shutdown(5);
		}

		pelog(LOG_DEBUG, "upstream: tell destination");
		uint8_t *p = buf, *req = buf;
		memcpy(p, "\x5\x1\x0", 3);
		memcpy(p += 3, destbin, destlen);
		memcpy(p += destlen, portbin, 2);
		p += 2;
		size_t reqlen = p - buf;
		write_data(upstream, req, reqlen);

		read_data(upstream, p, 5, 20000, false);
		if (p[0] != 5 || p[2] != 0) {
			exit_shutdown(1);
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
			exit_shutdown(1);
		}
		read_data(upstream, p + 5, left, timeout_short, false);

		if (p[1]) {
			req[1] = p[1];
			write_data(src, req, reqlen);
			exit_shutdown(-1);
		}
		pelog(LOG_DEBUG, "upstream: connect succeeded");
	}

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
	write_data(src, buf, addrlen + 6);

	retrieve_sock_info(true, upstream, destname, srcaddrbin, &port);

	pelog(LOG_DEBUG, "established: %s#%d <- %s#%d", destname, port, srcname, srcport);
	return upstream;
}

struct portpair {
	char const *rname, *wname;
	int r, w;
};

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
			pelog(LOG_NOTICE, "recv %s: error: %s", pp->rname, strerror(errno));
			break;
		} else if (readlen == 0) {
			break;
		}
//		pelog(LOG_DEBUG, "recv %s: %zd", pp->rname, readlen);
		recv_total += readlen;

		uint8_t *p = buf;
		while (readlen) {
			ssize_t writelen = send(pp->w, p, readlen, MSG_NOSIGNAL);
			if (writelen == -1) {
				pelog(LOG_NOTICE, "send %s: send(): %s", pp->wname, strerror(errno));
				goto CLOSE;
			}
//			pelog(LOG_DEBUG, "send %s: %zd in %zd", pp->wname, writelen, readlen);
			readlen -= writelen;
			p += writelen;
			send_total += writelen;
		}
	}
CLOSE:
	shutdown(pp->w, SHUT_WR);
	shutdown(pp->r, SHUT_RD);
	pelog(LOG_DEBUG, "total: recv %s: %zu, send %s: %zu",
		pp->rname, recv_total, pp->wname, send_total
	);
	pelog(LOG_DEBUG, "shutdown: %s -> %s", pp->rname, pp->wname);

	return NULL;
}

void *do_socks(void *sockpair_) {
	int *sockpair = sockpair_;
	pthread_setspecific(sock_cleaner, sockpair);
	int src = sockpair[0];

	char accept[40];
	uint16_t port;
	retrieve_sock_info(false, src, accept, NULL, &port);
	pelog(LOG_DEBUG, "accept: %s#%d", accept, port);

	int upstream = parse_header(src);
	pthread_t th;
	char const * const local = "local";
	char const * const remote = "remote";
	pthread_create(&th, NULL, do_relay, &(struct portpair) {
		.r = upstream, .rname = remote,
		.w = src, .wname = local,
	});
	do_relay(&(struct portpair) {
		.r = src, .rname = local,
		.w = upstream, .wname = remote,
	});
	pthread_join(th, NULL);
	return NULL;
}

