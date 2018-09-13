#include <poll.h>
#include <stdint.h>

struct petls {
	char reqhost[262], id[9];
	int src, dest;
	struct timespec btime;
};

struct rule {
	enum {
		rule_all,
		rule_host,
		rule_domain,
		rule_net4,
		rule_net6,
	} type;
	union {
		struct {
			char *name;
		} host;
		struct {
			uint8_t addr[4];
			uint8_t cidr;
		} net4;
		struct {
			uint8_t addr[16];
			uint8_t cidr;
		} net6;
	} u;
	uint16_t *ports;
	size_t port_num;
	struct proxy {
		enum {
			proxy_type_deny,
			proxy_type_socks5,
			proxy_type_socks4a,
			proxy_type_unix_socks5,
			proxy_type_http_connect,
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
int do_accept(struct pollfd *pfd, size_t bind_num);

// common.c
int retrieve_sock_info(
		bool peer,
		int fd,
		char addrname[static 40],
		uint8_t addrbin[static 16],
		uint16_t *port);
long lapse_ms(struct timespec *from);
bool end_with(char const *haystack, char const *needle);
char *downcase(char *s);
bool simple_host_check(char const *host);

// logger.c
void pelog_open(bool use_syslog, int loglevel);

// parse-rules.c
void load_rules(void);
void delete_rules(void);
struct rule *match_rule(char const *host, uint16_t port);
