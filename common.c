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
#include <time.h>
#include <sys/un.h>
#include <ctype.h>
#include <assert.h>

#include "privacy-exposer.h"
#include "global.h"

#define ADDR_MAX 64

int retrieve_sock_info(
		bool peer,
		int fd,
		char addrname[static ADDR_MAX], // ipv6アドレス格納。スコープIDが含まれる可能性があるので長めに
		uint8_t *addrbin, // NULLでなければ16バイト以上あることを保証すること
		uint16_t *port) {
	uint8_t buf[128], portbin[2], addrbin_dummy[16];
	char txtport[6];
	
	if (!addrbin) addrbin = addrbin_dummy; 
	
	struct sockaddr *addr = (void*)buf;
	socklen_t addrlen = 128;
	(peer ? getpeername : getsockname)(fd, addr, &addrlen);
	int type = addr->sa_family;
	if (type == AF_UNIX) {
		struct sockaddr_un *un = (void*)addr;
		strncpy(addrname, un->sun_path, ADDR_MAX);
		if (addrname[ADDR_MAX - 1] != '\0') {
			strcpy(&addrname[ADDR_MAX - 6], "//...");
		}
		*port = 0;
	}
	else {
		getnameinfo(addr, addrlen, addrname, ADDR_MAX, txtport, 6, NI_NUMERICHOST | NI_NUMERICSERV);
		*port = atoi(txtport);
		inet_pton(type, addrname, addrbin);
	}
	
	return type;
}

long lapse_ms(struct timespec *from) {
	struct timespec lap;
	clock_gettime(CLOCK_REALTIME, &lap);
	int seclap = lap.tv_sec - from->tv_sec;
	long nanolap = lap.tv_nsec - from->tv_nsec;
	if (nanolap < 0) nanolap += 1000000000;
	return seclap * 1000 + nanolap / 1000000;
}

bool end_with(char const *haystack, char const *needle) {
	size_t hlen = strlen(haystack);
	size_t nlen = strlen(needle);
	return hlen >= nlen && !strcmp(haystack + hlen - nlen, needle);
}

char *downcase(char *s) {
	char *r = s;
	while (*s) *s = tolower(*s), s++;
	return r;
}

bool simple_host_check(char const *host) {
	// 実際に接続を行うところでライブラリにエラーチェックをさせるので、
	// ここでは文字種の確認に留める
	if (strlen(host) != strspn(host,
		strchr(host, ':') ?
			"0123456789abcdefABCDEF.:" :
			"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._"
		)) return false;
	if (*host == '-'
		|| strstr(host, "..")
		|| strstr(host, ".-")
		|| strstr(host, "-.")
		|| end_with(host, "-")
		|| end_with(host, ".")) return false;
	return true;
}

size_t fgets_bin(char *buf, size_t len, FILE *fp) {
	assert(buf && fp);
	static size_t const errval = (size_t)-1;
	int c;
	if (len <= 1) {
		c = fgetc(fp);
		if (c == EOF) return errval;
		if (len) {
			ungetc(c, fp);
			*buf = '\0';
		}
		return 0;
	}

	char fmt[32];
	sprintf(fmt, "%%%zu[^\n]%%zn", len - 2);
	size_t readlen = 0;
	int ret = fscanf(fp, fmt, buf, &readlen);
	if (ret == EOF) return errval;
	c = fgetc(fp);
	if (!ret && c == EOF) return errval;
	if (c != EOF) buf[readlen++] = c;
	buf[readlen] = '\0';
	return readlen;
}
