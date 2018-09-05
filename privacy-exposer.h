struct petls {
	int src, dest;
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
void pelog_not_syslog(int priority, char const *fmt, ...);
void pelog_set_level(int pri);
