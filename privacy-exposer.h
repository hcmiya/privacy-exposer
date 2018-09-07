struct petls {
	char reqhost[262], id[9];
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
bool end_with(char const *haystack, char const *needle);

// logger.c
void pelog_open(bool use_syslog, int loglevel);
