struct petls {
	char reqhost[262], id[9];
	int src, dest;
	struct timespec btime;
};

struct rule {
	enum {
		rule_host,
		rule_net4,
		rule_net6,
	} type;
	union {
		struct {
			char *name;
			uint16_t *ports;
			size_t port_num;
		} host;
	} u;
	struct proxy {
		enum {
			proxy_type_socks5,
			proxy_type_deny,
			proxy_type_socks4a,
			proxy_type_unix_socks5,
		} type;
		union {
			struct {
				char *name;
				char port[6];
			} host_port;
			char *path;
		} u;
		struct proxy *next;
	} *proxy;
	struct rule *next;
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

// parse-rules.c
void parse_rules(FILE *fp);
