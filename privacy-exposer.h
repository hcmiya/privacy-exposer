#if !defined(__STDC_VERSION__) || __STDC_VERSION__ - 0 < 199901L
#error "Requires C99 or later compiler to build"
#endif

#include <stdint.h>
#include <sys/socket.h>

struct petls {
	char reqhost[262]; // ホスト名最長255 + '#' + ポート番号 + '\0'
	char id[9];
	uint8_t rtnbuf[262]; // socks5返答最長
	size_t rtnlen;
	int src, dest;
	struct timespec btime;
};

struct rule {
	ssize_t idx;
	enum {
		rule_all,
		rule_host,
		rule_domain,
		rule_net4,
		rule_net6,
		rule_net4_resolve,
		rule_net6_resolve,
		rule_fnmatch,
	} type;
	union {
		struct {
			char *name;
		} host;
		struct {
			sa_family_t af;
			uint8_t cidr;
			uint8_t addr[16];
		} net;
		char *pattern;
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
			uint8_t deny_by;
		} u;
		struct proxy *next;
		bool do_not_free;
	} *proxy;
	struct rule *next;
};

// socks.c
void read_header(int fd, void *buf_, size_t left, int timeout, bool atgreet);
void write_header(int fd, void const *buf_, size_t left);

// common.c
int retrieve_sock_info(
		bool peer,
		int fd,
		char addrname[static 46],
		uint8_t *addrbin,
		uint16_t *port);
long lapse_ms(struct timespec *from);
bool end_with(char const *haystack, char const *needle);
char *downcase(char *s);
bool simple_host_check(char const *host);
size_t fgets_bin(char *buf, size_t len, FILE *fp);

// logger.c
void pelog_open(bool use_syslog, int loglevel);

// parse-rules.c
void load_rules(void);
void delete_rules(void);
struct rule *match_rule(char const *host, uint16_t port);
struct rule *match_net_resolve(ssize_t maxidx, struct sockaddr *target);

// worker.c
