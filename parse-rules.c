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
#include <inttypes.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <fnmatch.h>

#include "privacy-exposer.h"
#include "global.h"

static size_t lineno = 1;

// デフォルトで接続を拒否するアドレスたちの為の定義
static struct proxy const deny_no_route = {
	.type = proxy_type_deny,
	.u.deny_by = 3,
	.do_not_free = true,
};

#define ALL_PORT_DENY_NO_ROUTE \
	.ports = (uint16_t[]){0, 65535}, \
	.port_num = 2, \
	.proxy = (struct proxy*)&deny_no_route

static struct rule rule_default[] = {
	{
		// fe80::/10
		.type = rule_net6_resolve,
		.u.net = {
			.af = AF_INET6,
			.cidr = 10,
			.addr = "\xfe\x80",
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
	{
		// 2001::db8::/32
		.type = rule_net6_resolve,
		.u.net = {
			.af = AF_INET6,
			.cidr = 32,
			.addr = "\x20\x01\x0d\xb8",
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
	{
		// 100::/64
		.type = rule_net6_resolve,
		.u.net = {
			.af = AF_INET6,
			.cidr = 64,
			.addr = "\x01",
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
	{
		// ::/96 除く ::1
		.type = rule_net6_resolve,
		.u.net = {
			.af = AF_INET6,
			.cidr = 96,
			.addr = "",
			.exceptcidr = 128,
			.exceptaddr = {[15] = 1},
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
	{
		// 0.0.0.0/8
		.type = rule_net4_resolve,
		.u.net = {
			.af = AF_INET,
			.cidr = 8,
			.addr = {0},
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
	{
		// 169.254.0.0/16
		.type = rule_net4_resolve,
		.u.net = {
			.af = AF_INET,
			.cidr = 16,
			.addr = {169, 254, 0, 0},
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
	{
		// 192.0.2.0/24
		.type = rule_net4_resolve,
		.u.net = {
			.af = AF_INET,
			.cidr = 24,
			.addr = {192, 0, 2, 0},
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
	{
		// 198.51.100/24
		.type = rule_net4_resolve,
		.u.net = {
			.af = AF_INET,
			.cidr = 24,
			.addr = {198, 51, 100, 0},
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
	{
		// 203.0.113.0/24
		.type = rule_net4_resolve,
		.u.net = {
			.af = AF_INET,
			.cidr = 24,
			.addr = {203, 0, 113, 0},
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
	{
		// 240.0.0.0/4
		.type = rule_net4_resolve,
		.u.net = {
			.af = AF_INET,
			.cidr = 4,
			.addr = {240, 0, 0, 0},
		},
		ALL_PORT_DENY_NO_ROUTE,
	},
};
#undef ALL_PORT_DENY_NO_ROUTE
static ssize_t const rule_default_num = sizeof(rule_default) / sizeof(*rule_default);
static struct rule * const rule_default_end = &rule_default[sizeof(rule_default) / sizeof(*rule_default) - 1];
// デフォルトで接続を拒否するアドレスたちの為の定義 ここまで

static struct rule *rule_cur, **rule_resolve_list;
static size_t rule_resolve_num;
static struct proxy proxy_begin, *proxy_cur;

static void error(char const *fmt, ...) {
	char linefmt[1536];
	sprintf(linefmt, "line #%zu: %s", lineno, fmt);
	va_list ap;
	va_start(ap, fmt);
	vpelog(LOG_CRIT, linefmt, ap);
	va_end(ap);
	if (!first_worker) {
		kill(root_process, SIGQUIT);
	}
	exit(2);
}

static int32_t parse_u16(char *s) {
	char *endp;
	unsigned long val = strtoul(s, &endp, 10);
	if (s == endp || val > 65535) return -1;
	return (int32_t)val;
}

static struct proxy *new_proxy_ent(int type) {
	proxy_cur = (proxy_cur->next = calloc(1, sizeof(*proxy_cur)));
	proxy_cur->type = type;
	return proxy_cur;
}

static struct rule *new_rule_ent(int type) {
	rule_cur = (rule_cur->next = calloc(1, sizeof(*rule_cur)));
	rule_cur->type = type;
	return rule_cur;
}

static size_t parse_proxy_hostname(char **fields, size_t fieldnum, char *name, int type) {
	if (fieldnum < 2) {
		error("too few arguments for %s", name);
	}
	size_t fieldnum_sav = fieldnum;

	char *host = *fields++;
	char *port = *fields++;
	fieldnum -= 2;
	downcase(host);

	bool hostpass = false;
	do {
		if (strncmp("fe80:", host, 5) == 0) {
			// IPv6リンクローカルアドレス。後ろに処理系定義のインターフェイス名識別子を付けないと使えず、
			// その構文の検証をsimple_host_check()で行えないためgetaddrinfo()を使う。
			struct addrinfo *res;
			int gairet = getaddrinfo(host, port, &(struct addrinfo) {
				.ai_family = AF_INET6,
				.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
			}, &res);
			if (gairet) break;
			struct sockaddr_in6 *i6 = (struct sockaddr_in6 *)res->ai_addr;
			hostpass = !!i6->sin6_scope_id;
			freeaddrinfo(res);
			break;
		}
		if (simple_host_check(host)) {
			hostpass = *host != '.';
			break;
		}
	} while (false);
	if (!hostpass) {
		error("invalid host for %s: %s", name, host);
	}

	size_t len = 0;
	char *pp = port;
	int32_t portint = 0;
	while (*pp && len < 5) {
		if (!isdigit(*pp)) {
			break;
		}
		portint = portint * 10 + *pp - '0';
		pp++;
		len++;
	}
	if (*pp || portint > 65535) {
		error("invalid port for %s: ", name, port);
	}

	struct proxy *proxy = new_proxy_ent(type);
	proxy->u.host_port.name = strdup(host);
	strcpy(proxy->u.host_port.port, port);
	return fieldnum_sav - fieldnum;
}

static size_t parse_proxy_abs_path(char **fields, size_t fieldnum, char *name, int type) {
	if (proxy_cur != &proxy_begin) {
		error("\"%s\" can not be used for proxy chain", name);
	}
	if (fieldnum < 1) {
		error("too few arguments for %s", name);
	}
	if (**fields != '/') {
		error("invalid path for %s: %s", name, *fields);
	}
	struct proxy *proxy = new_proxy_ent(type);
	proxy->u.path = strdup(*fields);
	return 1;
}

static size_t parse_proxy_deny(char **fields, size_t fieldnum, char *name, int type) {
	if (proxy_cur != &proxy_begin) {
		error("\"deny\" can not be used for proxy chain");
	}
	if (fieldnum > 0) {
		error("too many arguments for deny");
	}
	static struct proxy const deny = {
		.type = proxy_type_deny,
		.u.deny_by = 2,
		.do_not_free = true,
	};
	proxy_cur->next = (struct proxy*)&deny;
	return 0;
}

static size_t parse_port(char *strport, uint16_t **portlist) {
	if (!strport || !*strport) {
		*portlist = calloc(2, sizeof(**portlist));
		(*portlist)[1] = 65535;
		return 2;
	}

	size_t comma_num = 0;
	char *p = strport;
	while (*p) {
		if (*p++ == ',') {
			comma_num++;
		}
	}
	uint16_t *accept_ports = calloc((comma_num + 1) * 2, sizeof(*accept_ports));
	size_t parsed = 0;
	p = strport;
	while (*p) {
		char *strlowerport = p, *strupperport;
		bool has_range = false;
		while (isdigit(*p)) p++;
		if (*p == '-') {
			has_range = true;
			strupperport = ++p;
		}
		else if (*p == ',') {
			if (p == strlowerport) {
				p++;
				continue;
			}
			strupperport = p;
		}
		else if (*p == '\0') {
			strupperport = p;
		}
		else {
			error("invalid port: %s", strport);
		}
		while (isdigit(*p)) p++;
		if (!(*p == ',' || *p == '\0') || *strlowerport == '-' && !isdigit(*strupperport)) {
			error("invalid port: %s", strport);
		}
		if (isdigit(*strlowerport)) {
			int32_t val = parse_u16(strlowerport);
			if (val < 0) error("invalid port: %s", strport);
			accept_ports[parsed] = val;
		}
		else {
			accept_ports[parsed] = 0;
		}
		if (isdigit(*strupperport)) {
			int32_t val = parse_u16(strupperport);
			if (val < 0) error("invalid port: %s", strport);
			accept_ports[parsed + 1] = val;
		}
		else {
			accept_ports[parsed + 1] = has_range ? 65535 : accept_ports[parsed];
		}
		if (accept_ports[parsed] > accept_ports[parsed + 1]) {
			uint16_t tmp = accept_ports[parsed];
			accept_ports[parsed] = accept_ports[parsed + 1];
			accept_ports[parsed + 1] = tmp;
		}
		parsed += 2;
		if (*p == ',') p++;
	}
	if (!parsed) {
		accept_ports[0] = 0;
		accept_ports[1] = 65535;
		parsed = 2;
	}
	*portlist = accept_ports;
	return parsed;
}

static size_t parse_rule_host(char **fields, size_t fieldnum, char const *name, int type) {
	if (fieldnum < 1) {
		error("no arguments for %s", name);
	}
	size_t rtn = 0;
	char *host = *fields;

	if (*host == '#') {
		host = "";
	}
	else if (simple_host_check(host)) {
		fields++;
		rtn++;
	}
	else {
		error("invalid domain name: %s", host);
	}

	char *port = *fields++;
	if (port && *port == '#') {
		port++;
		rtn++;
	}
	else port = NULL;
	if (!*host && !port) {
		error("no rule for %s", name);
	}

	uint16_t *port_list;
	size_t port_num = parse_port(port, &port_list);

	struct rule *rule = new_rule_ent(type);
	rule->u.host.name = strdup(host);
	rule->ports = port_list;
	rule->port_num = port_num;
	return rtn;
}

static size_t parse_rule_all(char **unused, size_t fieldnum, char const *name, int type) {
	struct rule *rule = new_rule_ent(type);
	return 0;
}

static uint8_t parse_cidr(char const *str, int max) {
	int_fast16_t cidr = 0;
	int i;
	for (i = 0; isdigit(str[i]) && i < 3; i++) {
		cidr *= 10;
		cidr += str[i] - '0';
	}
	if (i == 0 || str[i] != '\0' || str[0] == '0' && str[1] != '\0' || cidr > max) {
		error("invalid cidr: /%s", str);
	}
	return cidr;
}

static bool test_net(void *target_, void *test_, uint8_t cidr) {
	uint8_t *target = target_, *test = test_;
	while (cidr >= 8) {
		if (*target++ != *test++) return false;
		cidr -= 8;
	}
	int left = 8 - cidr;
	return !cidr || (*target >> left) == (*test >> left);
}

static size_t parse_rule_net(char **fields, size_t fieldnum, char const *name, int type) {
	if (fieldnum < 1) {
		error("no arguments for %s", name);
	}

	size_t fieldnum_sav = fieldnum;
	uint8_t addr[16] = "";
	uint8_t cidr;
	uint8_t addrlen;
	int addrtype;
	uint8_t cidrmax;
	char const *protoname;

	switch (type) {
	case rule_net4:
	case rule_net4_resolve:
		cidrmax = 32;
		addrtype = AF_INET;
		addrlen = 4;
		protoname = "ipv4";
		break;
	case rule_net6:
	case rule_net6_resolve:
		cidrmax = 128;
		addrtype = AF_INET6;
		addrlen = 16;
		protoname = "ipv6";
		break;
	}

	if (**fields == '#') {
		cidr = 0;
	}
	else {
		char *straddr = *fields++;
		fieldnum--;
		char *strcidr = strchr(straddr, '/');
		if (strcidr) *strcidr++ = '\0';
		if (!inet_pton(addrtype, straddr, addr)) {
			error("invalid %s address: %s", protoname, straddr);
		}
		if (strcidr) {
			cidr = parse_cidr(strcidr, cidrmax);
		}
		else {
			cidr = cidrmax;
		}
	}

	char *port = *fields;
	if (port && *port++ == '#') {
		fields++;
		fieldnum--;
	}
	else port = NULL;
	uint16_t *port_list;
	size_t port_num = parse_port(port, &port_list);

	// 除外ネットワーク
	uint8_t exceptaddr[16];
	uint8_t exceptcidr = 0;
	if (*fields && strcmp(*fields, "except") == 0) {
		fields++;
		fieldnum--;
		if (!fieldnum) {
			error("no argument for except address");
		}
		char *strexcept = *fields++;
		fieldnum--;
		char *strcidr = strchr(strexcept, '/');
		if (strcidr) {
			*strcidr++ = '\0';
		}
		if (!inet_pton(addrtype, strexcept, exceptaddr)) {
			error("invalid %s address: %s", protoname, strexcept);
		}
		if (!test_net(addr, exceptaddr, cidr)) {
			error("except network is not part of the base network");
		}
		exceptcidr = strcidr ? parse_cidr(strcidr, cidrmax) : cidrmax;
		if (exceptcidr <= cidr) {
			// ※ネットワークが小さい ⇒ CIDRが大きい
			error("except network (/%d) must be smaller than the base network (/%d)", exceptcidr, cidr);
		}
	}

	struct rule *rule = new_rule_ent(type);
	rule->u.net.af = addrtype;
	memcpy(rule->u.net.addr, addr, addrlen);
	memcpy(rule->u.net.exceptaddr, exceptaddr, addrlen);
	rule->u.net.cidr = cidr;
	rule->u.net.exceptcidr = exceptcidr;
	rule->ports = port_list;
	rule->port_num = port_num;

	return fieldnum_sav - fieldnum;
}

static size_t parse_rule_fnmatch(char **fields, size_t fieldnum, char const *name, int type) {
	if (fieldnum < 1) {
		error("no arguments for %s", name);
	}

	size_t fieldnum_sav = fieldnum;
	char const *pattern = *fields++;
	fieldnum--;
	if (*pattern == '#') {
		error("invalid pattern: ", pattern);
	}

	char *port = *fields;
	if (port && *port++ == '#') {
		fields++;
		fieldnum--;
	}
	else port = NULL;
	uint16_t *port_list;
	size_t port_num = parse_port(port, &port_list);

	struct rule *rule = new_rule_ent(type);
	rule->u.pattern = strdup(pattern);
	rule->ports = port_list;
	rule->port_num = port_num;

	return fieldnum_sav - fieldnum;
}

static void parse_fields(char **fields, size_t fieldnum) {
	struct match_table_ {
		char const *name;
		size_t (*parser)(char **, size_t, char const *, int);
		int type;
	};
	static struct match_table_ const match_table[] = {
		{ "all", parse_rule_all, rule_all },
		{ "host", parse_rule_host, rule_host },
		{ "domain", parse_rule_host, rule_domain },
		{ "net4", parse_rule_net, rule_net4 },
		{ "net6", parse_rule_net, rule_net6 },
		{ "net4-resolve", parse_rule_net, rule_net4_resolve },
		{ "net6-resolve", parse_rule_net, rule_net6_resolve },
		{ "fnmatch", parse_rule_fnmatch, rule_fnmatch },
		{ NULL, NULL, 0 },
	};
	struct match_table_ const *mtp = match_table;
	size_t i, adv;
	int rule_type;
	for (mtp = match_table; mtp->name; mtp++) {
		if (strcmp(*fields, mtp->name) == 0) {
			adv = mtp->parser(++fields, --fieldnum, mtp->name, mtp->type);
			break;
		}
	}
	if (!mtp->name) {
		error("unknown matcher directive: %s", *fields);
	}
	fields += adv;
	fieldnum -= adv;

	struct proxy_table_ {
		char *name;
		int type;
		size_t (*parser)(char **, size_t, char *, int);
	};
	static struct proxy_table_ const proxy_table[] = {
		{ "deny", proxy_type_deny, parse_proxy_deny },
		{ "socks5", proxy_type_socks5, parse_proxy_hostname },
		{ "socks4a", proxy_type_socks4a, parse_proxy_hostname },
		{ "unix-socks5", proxy_type_unix_socks5, parse_proxy_abs_path },
		{ "http-connect", proxy_type_http_connect, parse_proxy_hostname },
		{ NULL, 0, NULL },
	};
	proxy_cur = &proxy_begin;
	proxy_cur->next = NULL;
	while (*fields) {
		struct proxy_table_ const *ptp;
		for (ptp = proxy_table; ptp->name; ptp++) {
			if (strcmp(*fields, ptp->name) == 0) {
				adv = ptp->parser(++fields, --fieldnum, ptp->name, ptp->type);
				break;
			}
		}
		if (!ptp->name) {
			error("unknown proxy directive: %s", *fields);
		}
		fields += adv;
		fieldnum -= adv;
	}
	switch (mtp->type) {
	case rule_net4_resolve:
	case rule_net6_resolve:
		rule_resolve_num++;
		break;
	}
	rule_cur->idx = lineno;
	rule_cur->proxy = proxy_begin.next;
}

void parse_rules(FILE *fp) {
	rule_cur = rule_default_end;
	rule_resolve_num = rule_default_num;
	size_t const buflen = 1024;
	char line[buflen];
	lineno = 1;

	for (size_t linelen; (linelen = fgets_bin(line, buflen, fp)) != (size_t)-1; lineno++) {
		if (linelen != strlen(line)) {
			error("binary file");
		}
		if (linelen == buflen - 1 && line[linelen - 1] != '\n') {
			int c = fgetc(fp);
			if (c != '\n' && c != EOF) {
				error("exceeds %zu characters", buflen - 1);
			}
		}

		char *p = strchr(line, ';');
		if (p) *p = '\0';

		size_t fieldnum = 0;
		p = line;
		while (*p) {
			while (*p && isspace(*p)) {
				*p++ = '\0';
			}
			if (!*p) break;
			fieldnum++;
			while (*p && !isspace(*p)) p++;
		}
		if (!fieldnum) continue;

		char *fields[fieldnum + 1];
		p = line;
		for (size_t i = 0; i < fieldnum; i++) {
			while (!*p) p++;
			fields[i] = p;
			p = strchr(fields[i], '\0');
		}
		fields[fieldnum] = NULL;
		parse_fields(fields, fieldnum);
	}
	if (ferror(fp)) {
		error("%s", strerror(errno));
	}

	// 最後は全てにマッチするルールで終端させる
	if (rule_cur == rule_default_end || rule_cur->type != rule_all) {
		parse_fields((char *[]){"all", NULL}, 1);
	}

	rule_resolve_list = calloc(rule_resolve_num + 1, sizeof(*rule_resolve_list));
	size_t i = 0;
	for (rule_cur = rule_default; i < rule_resolve_num; rule_cur = rule_cur->next) {
		switch (rule_cur->type) {
		case rule_net4_resolve:
		case rule_net6_resolve:
			rule_resolve_list[i++] = rule_cur;
			break;
		}
	}
}

void delete_rules(void) {
	struct rule *r = rule_default_end->next;
	while (r) {
		switch (r->type) {
		case rule_host:
		case rule_domain:
			free(r->u.host.name);
			break;
		}
		free(r->ports);

		for (struct proxy *p = r->proxy; p; ) {
			switch (p->type) {
			case proxy_type_socks5:
			case proxy_type_socks4a:
			case proxy_type_http_connect:
				free(p->u.host_port.name);
				break;
			case proxy_type_unix_socks5:
				free(p->u.path);
				break;
			}

			p = p->next;
			if (!r->proxy->do_not_free) {
				free(r->proxy);
			}
			r->proxy = p;
		}

		r = r->next;
		free(rule_default_end->next);
		rule_default_end->next = r;
	}
	free(rule_resolve_list);
	rule_resolve_list = NULL;
}

void load_rules(void) {
	assert(rule_file_path);
	FILE *rfp = fopen(rule_file_path, "r");
	if (!rfp) {
		pelog(LOG_CRIT, "%s: %s", rule_file_path, strerror(errno));
		exit(1);
	}
	if (first_worker) {
		size_t i;
		for (i = 0; i < rule_default_num - 1; i++) {
			rule_default[i].idx = -rule_default_num + i + 1;
			rule_default[i].next = &rule_default[i + 1];
		}
	}
	parse_rules(rfp);
	fclose(rfp);
}

static bool match_port(uint16_t port, uint16_t *ports, size_t num) {
	for (int i = 0; i < num; i += 2) {
		if (port >= ports[i] && port <= ports[i + 1]) return true;
	}
	return false;
}

static bool match_net(struct rule *rule, int addrtype, uint8_t *addr, uint16_t port) {
	return test_net(addr, rule->u.net.addr, rule->u.net.cidr)
		&& match_port(port, rule->ports, rule->port_num)
		&& (!rule->u.net.exceptcidr || !test_net(addr, rule->u.net.exceptaddr, rule->u.net.exceptcidr));
}

struct rule *match_rule(char const *host, uint16_t port) {
	struct rule *rule = rule_default;

	while (rule) {
		bool rule_matched = false;
		switch (rule->type) {
		case rule_all:
			return rule;
		case rule_host:
		case rule_domain:
			{
				bool host_matched = false;
				char const *needle = rule->u.host.name;
				if (!*needle) {
					host_matched = true;
				}
				else if (*needle == '.') {
					host_matched = end_with(host, needle);
				}
				else switch (rule->type) {
				case rule_host:
					host_matched = strcmp(host, needle) == 0;
					break;
				case rule_domain:
					if (end_with(host, needle)) {
						size_t hostlen = strlen(host);
						size_t needlelen = strlen(needle);
						host_matched = hostlen == needlelen || host[hostlen - needlelen - 1] == '.';
					}
					break;
				}
				if (host_matched) {
					if (match_port(port, rule->ports, rule->port_num)) return rule;
				}
			}
			break;
		case rule_net4:
		case rule_net6:
		case rule_net4_resolve:
		case rule_net6_resolve:
			{
				uint8_t addr[16];
				int addrtype;
				socklen_t addrlen;
				switch (rule->type) {
				case rule_net4:
				case rule_net4_resolve:
					addrtype = AF_INET;
					addrlen = 4;
					break;
				case rule_net6:
				case rule_net6_resolve:
					addrtype = AF_INET6;
					addrlen = 16;
					break;
				}
				int parsed_as_ipv6 = inet_pton(AF_INET6, host, addr);
				if (parsed_as_ipv6) {
					if (addrtype == AF_INET) {
						// 入力がIPv4射影アドレスかNAT64 prefixの場合はIPv4として検査する
						bool v4mapped = true;
						do {
							// ::ffff:0:0/96
							// if (test_net("\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xff\xff\x0\x0\x0\x0", addr, 96)) break;
							if (memcmp("\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xff\xff", addr, 12) == 0) break;
							// 64:ff9b::/96 (well known)
							if (memcmp("\x0\x64\xff\x9b\x0\x0\x0\x0\x0\x0\x0\x0", addr, 12) == 0) break;
							v4mapped = false;
						} while (false);
						if (v4mapped) {
							addrtype = AF_INET;
							memcpy(addr, &addr[12], 4);
						}
						else break;
					}
				}
				else {
					if (addrtype == AF_INET) {
						if (!inet_pton(AF_INET, host, addr)) break;
					}
					else break;
				}
				if (match_net(rule, addrtype, addr, port)) return rule;
			}
			break;
		case rule_fnmatch:
			if (fnmatch(rule->u.pattern, host, 0) == 0 && match_port(port, rule->ports, rule->port_num)) return rule;
			break;
		}
	NEXT_RULE:
		rule = rule->next;
	}
	assert(!"can't be reached here");
	return NULL;
}

struct rule *match_net_resolve(ssize_t maxidx, struct sockaddr *target) {
	uint8_t *addr;
	uint16_t port;
	switch (target->sa_family) {
	case AF_INET:
		addr = (uint8_t*)&((struct sockaddr_in*)target)->sin_addr;
		port = ntohs(((struct sockaddr_in*)target)->sin_port);
		break;
	case AF_INET6:
		addr = (uint8_t*)&((struct sockaddr_in6*)target)->sin6_addr;
		port = ntohs(((struct sockaddr_in6*)target)->sin6_port);
		break;
	}

	struct rule **r = rule_resolve_list;
	while (*r && (*r)->idx < maxidx) {
		struct rule *dr = *r;
		if (target->sa_family == dr->u.net.af
			&& match_net(dr, target->sa_family, addr, port)) return dr;
		r++;
	}
	return NULL;
}
