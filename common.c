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

static int level = LOG_DEBUG;
void pelog_set_level(int pri) {
	level = pri;
}
void pelog_not_syslog(int priority, char const *fmt, ...) {
	if (priority > level) return;
	printf("%jd: ", (intmax_t)pthread_self());

	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}
