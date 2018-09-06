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

#include "privacy-exposer.h"
#include "global.h"

int retrieve_sock_info(
		bool peer,
		int fd,
		char addrname[static 40],
		uint8_t addrbin[static 16],
		uint16_t *port) {
	uint8_t buf[128], portbin[2], addrbin_dummy[16];
	char txtport[6];
	
	if (!addrbin) addrbin = addrbin_dummy; 
	
	struct sockaddr *addr = (void*)buf;
	socklen_t addrlen = 128;
	(peer ? getpeername : getsockname)(fd, addr, &addrlen);
	getnameinfo(addr, addrlen, addrname, 40, txtport, 6, NI_NUMERICHOST | NI_NUMERICSERV);
	
	int type = addr->sa_family;
	*port = atoi(txtport);
	inet_pton(type, addrname, addrbin);
	
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

static int level = LOG_DEBUG;
void pelog_set_level(int pri) {
	level = pri;
}

void pelog_not_syslog(int priority, char const *fmt, ...) {
	if (priority > level) return;

	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}

void pelog_not_syslog_th(int priority, char const *fmt, ...) {
	if (priority > level) return;

	struct petls *tls = pthread_getspecific(sock_cleaner);
	printf("%s: %ldms: ", tls->id, lapse_ms(&tls->btime));

	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}

void vpelog_not_syslog(int priority, char const *fmt, va_list ap) {
	if (priority > level) return;
	va_list copyap;
	va_copy(copyap, ap);
	vprintf(fmt, copyap);
	va_end(copyap);
	putchar('\n');
}

void pelog_syslog_th(int priority, char const *fmt, ...) {
	struct petls *tls = pthread_getspecific(sock_cleaner);

	char fmt_with_id[256];
	sprintf(fmt_with_id, "%s: %ldms: %s", tls->id, lapse_ms(&tls->btime), fmt);

	va_list ap;
	va_start(ap, fmt);
	vsyslog(priority, fmt_with_id, ap);
	va_end(ap);
}
