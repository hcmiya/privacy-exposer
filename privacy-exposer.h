struct petls {
	char id[9];
	int src, dest;
	struct timespec btime;
};

// socks.c
void *do_socks(void *sockpair);

// common.c
int retrieve_sock_info(
		bool peer,
		int fd,
		char addrname[static 40],
		uint8_t addrbin[static 16],
		uint16_t *port);
long lapse_ms(struct timespec *from);

void pelog_not_syslog(int priority, char const *fmt, ...);
void pelog_not_syslog_th(int priority, char const *fmt, ...);
void vpelog_not_syslog(int priority, char const *fmt, va_list ap);
void pelog_syslog_th(int priority, char const *fmt, ...);
void pelog_set_level(int pri);
