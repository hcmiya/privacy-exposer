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

#ifdef NDEBUG
static int const timeout_read_upstream = 20000;
#else
static int const timeout_read_upstream = -1;
#endif

static int next_socks5(char const *host, char const *port, int upstream, int idx) {
	uint8_t buf[262];
	if (strlen(host) > 255) {
		pelog_th(LOG_INFO, "proxy #%d: too long hostname: %s", idx, host);
		return 1;
	}
	pelog_th(LOG_DEBUG, "proxy #%d: connect request", idx);
	write_header(upstream, "\x5\x1\x0", 3);
	read_header(upstream, buf, 2, timeout_read_short, false);
	if (buf[0] != 5 || buf[1] != 0) {
		return 5;
	}

	pelog_th(LOG_DEBUG, "proxy #%d: tell destination", idx);
	uint8_t *p = buf, *req = buf, hostlen = (uint8_t)strlen(host);
	uint16_t portbin = htons((uint16_t)atoi(port));
	memcpy(p, "\x5\x1\x0\x3", 4);
	memcpy(p += 4, &hostlen, 1);
	memcpy(p += 1, host, hostlen);
	memcpy(p += hostlen, &portbin, 2);
	p += 2;
	size_t reqlen = p - buf;
	write_header(upstream, req, reqlen);

	read_header(upstream, p, 5, timeout_read_upstream, false);
	if (p[0] != 5 || p[2] != 0) {
		return 1;
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
		return 1;
	}
	read_header(upstream, p + 5, left, timeout_read_short, false);

	return p[1];
}

static int next_socks4a(char const *host, char const *port, int upstream, int idx) {
	if (strlen(host) > 255) {
		pelog_th(LOG_INFO, "proxy #%d: too long hostname: %s", idx, host);
		return 1;
	}

	pelog_th(LOG_DEBUG, "proxy #%d: connect request", idx);
	uint8_t buf[265];
	// ver, connect, port, 0.0.0.1, nul
	memcpy(buf, "\x4\x1pp\x0\x0\x0\x1\x0", 9);
	memcpy(&buf[2], (uint16_t[]){htons((uint16_t)atoi(port))}, 2);
	strcpy((char*)&buf[9], host);
	write_header(upstream, buf, 9 + strlen(host) + 1);

	// ver, result, ign
	read_header(upstream, buf, 8, timeout_read_short, false);
	if (buf[0] != 0 || buf[1] != 90) {
		return 1;
	}
}

static ssize_t http_peek(int upstream, void *buf, size_t len) {
#ifdef NDEBUG
	int const timeout = 20
#else
	int const timeout = -1
#endif
	;
	struct pollfd pfd = {
		.fd = upstream,
		.events = POLLIN,
	};

	int poll_ret = poll(&pfd, 1, timeout);
	if (poll_ret == 0) {
		return -4;
	}
	if (poll_ret < 0) {
		return -3;
	}
	ssize_t readlen = recv(upstream, buf, len, MSG_PEEK);
	if (readlen < 0) {
		return -3;
	}
	return readlen;
}
static bool http_valid_char(int c) {
	return !(c >= 0x7f || c >= 0 && c < 0x20 && !strchr("\n\r\t", c));
}
static bool http_header_char(int c) {
	return !!strchr("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'*+-.^_`|~", c);
}

static int next_http_connect(char const *host, char const *port, int upstream, int idx) {
	size_t const buflen = 512;
	char buf[buflen];
	{
		size_t wlen;
		bool ipv6 = strchr(host, ':');
		char const *hostopen = ipv6 ? "[" : "";
		char const *hostclose = ipv6 ? "]" : "";
		// CONNECT host.example:80 HTTP/1.1
		// Host: host.example
		wlen = sprintf(buf, "CONNECT %s%s%s:%s HTTP/1.1\r\n", hostopen, host, hostclose, port);
		write_header(upstream, buf, wlen);
		wlen = sprintf(buf, "Host: %s%s%s\r\n\r\n", hostopen, host, hostclose);
		write_header(upstream, buf, wlen);

		// HTTP/1.1 200 OK
		// Header: ***
		read_header(upstream, buf, 13, timeout_read_upstream, false);
		if (memcmp(buf, "HTTP/1.1 ", 9) != 0) {
			return 1;
		}
		char *p = buf + 9;
		unsigned int st = 0;
		for (int i = 0; i < 3; i++) {
			if (!isdigit(*p)) {
				return 1;
			}
			st = st * 10 + (*p - '0');
			p++;
		}
		if (*p != ' ') {
			return 1;
		}
		if (st < 200 || st >= 300) {
			pelog_th(LOG_INFO, "proxy #%d: connection failed: %u", idx, st);
			return 1;
		}
	}

	// 1文字ずつ読み取っていって、\r\n\r\nに遭遇したら抜ける
	{
		// ステータス行残り
		bool cr = false, terminated = false, header = false;
		char *cur, *end;
		while (!terminated) {
			ssize_t len = http_peek(upstream, buf, buflen);
			if (len == 0) return 2;
			else if (len < 0) return 3;

			cur = buf; end = cur + len;
			while (cur < end) {
				int c = *cur++;
				if (!http_valid_char(c)) return 1;

				if (!cr && c == '\n') {
					return 1;
				}
				if (cr) {
					if (c != '\n') {
						return 1;
					}
					cr = false;
					terminated = true;
					break;
				}
				else {
					cr = c == '\r';
				}
			}
			read(upstream, buf, cur - buf);
		}

		// ヘッダ行(プロクシ返答なら本当は無いはず)
		bool established = false;
		while (!established) {
			ssize_t len = http_peek(upstream, buf, buflen);
			if (len == 0) return 2;
			else if (len < 0) return 3;

			cur = buf; end = cur + len;
			while (cur < end) {
				int c = *cur++;
				if (!http_valid_char(c)) return 1;

				if (!cr && c == '\n') {
					return 1;
				}
				if (cr) {
					if (c != '\n') {
						return 1;
					}
					if (terminated) {
						established = true;
						break;
					}
					else {
						cr = false;
						terminated = true;
					}
				}
				else if (header) {
					if (http_header_char(c)) {}
					else if (c == ':') header = false;
					else return 1;
				}
				else {
					if (terminated) {
						if (c == '\r') cr = true;
						else if (http_header_char(c)) {
							terminated = false;
							header = true;
						}
						else {
							return 1;
						}
					}
					else {
						cr = c == '\r';
					}
				}
			}
			read(upstream, buf, cur - buf);
		}
	}
	return 0;
}

int greet_next_proxy(char const *host, char const *port, struct proxy *proxy, int upstream) {
	if (upstream < 0) return upstream;

	int idx = 1;
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

		int error;
		switch (proxy->type) {
		case proxy_type_socks5:
		case proxy_type_unix_socks5:
			error = next_socks5(nexthost, nextport, upstream, idx);
			break;
		case proxy_type_socks4a:
			error = next_socks4a(nexthost, nextport, upstream, idx);
			break;
		case proxy_type_http_connect:
			error = next_http_connect(nexthost, nextport, upstream, idx);
			switch (error) {
			case 0:
				break;
			case 1:
				pelog_th(LOG_INFO, "proxy #%d: unexpected response", idx);
				break;
			case 2:
				pelog_th(LOG_INFO, "proxy #%d: unexpected eof", idx);
				break;
			case 3:
				pelog_th(LOG_INFO, "proxy #%d: error on recv()", idx);
				break;
			case 4:
				pelog_th(LOG_INFO, "proxy #%d: recv() timed out", idx);
				break;
			}
			if (error) error = 1;
			break;
		}
		if (error) {
			return -error;
		}

		pelog_th(LOG_DEBUG, "proxy #%d: connect succeeded", idx);
		proxy = proxy->next;
		idx++;
	}
	return upstream;
}

