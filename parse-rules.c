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

#include "privacy-exposer.h"
#include "global.h"

static size_t lineno = 1;

static struct rule rule_begin, *rule_cur;
static struct proxy proxy_begin, *proxy_cur;

static void error(char const *fmt, ...) {
	fprintf(stderr, "line #%zu: ", lineno);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	putchar('\n');
	exit(2);
}

static int32_t parse_u16(char *s) {
	char *endp;
	unsigned long val = strtoul(s, &endp, 10);
	if (s == endp || val > 65535) return -1;
	return (int32_t)val;
}

static size_t parse_proxy_hostname(char **fields, size_t fieldnum, char *name, int type) {
	if (fieldnum < 2) {
		error("too few arguments for %s", name);
	}
	if (!simple_host_check(*fields) || **fields == '.' || end_with(*fields, ".")) {
		error("invalid host for %s: %s", name, *fields);
	}
	size_t len = 0;
	char *pp = fields[1];
	while (*pp && len < 5) {
		if (!isdigit(*pp)) {
			break;
		}
		pp++;
		len++;
	}
	if (*pp) {
		error("invalid port for %s: ", name, fields[1]);
	}

	long val = strtoul(fields[1], NULL, 10);
	if (val > 65535) {
		error("invalid port for %s: ", name, fields[1]);
	}
	proxy_cur->next = calloc(1, sizeof(*proxy_cur));
	proxy_cur = proxy_cur->next;
	proxy_cur->type = type;
	proxy_cur->u.host_port.name = strdup(*fields);
	strcpy(proxy_cur->u.host_port.port, fields[1]);
	return 2;
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
	proxy_cur->next = calloc(1, sizeof(*proxy_cur));
	proxy_cur = proxy_cur->next;
	proxy_cur->type = type;
	proxy_cur->u.path = strdup(*fields);
	return 1;
}

static size_t parse_proxy_deny(char **fields, size_t fieldnum, char *name, int type) {
	if (proxy_cur != &proxy_begin) {
		error("\"deny\" can not be used for proxy chain");
	}
	if (fieldnum > 0) {
		error("too many arguments for deny");
	}
	static struct proxy deny = { .type = proxy_type_deny };
	proxy_cur->next = &deny;
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
	uint16_t *port_list;
	size_t port_num = parse_port(port, &port_list);

	rule_cur->next = calloc(1, sizeof(*rule_cur));
	rule_cur = rule_cur->next;
	rule_cur->type = type;
	rule_cur->u.host.name = strdup(host);
	rule_cur->ports = port_list;
	rule_cur->port_num = port_num;
	return rtn;
}

static size_t parse_rule_all(char **unused, size_t fieldnum, char const *name, int type) {
	rule_cur->next = calloc(1, sizeof(*rule_cur));
	rule_cur->type = type;
	rule_cur = rule_cur->next;
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
		cidrmax = 32;
		addrtype = AF_INET;
		addrlen = 4;
		protoname = "ipv4";
		break;
	case rule_net6:
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

	rule_cur->next = calloc(1, sizeof(*rule_cur));
	rule_cur = rule_cur->next;
	rule_cur->type = type;
	memcpy(rule_cur->u.net.addr, addr, addrlen);
	rule_cur->u.net.cidr = cidr;
	rule_cur->ports = port_list;
	rule_cur->port_num = port_num;

	return fieldnum_sav - fieldnum;
}

static void parse_fields(char **fields, size_t fieldnum) {
	static struct {
		char const *name;
		size_t (*parser)(char **, size_t, char const *, int);
		int type;
	} const match_table[] = {
		{ "all", parse_rule_all, rule_all },
		{ "host", parse_rule_host, rule_host },
		{ "domain", parse_rule_host, rule_domain },
		{ "net4", parse_rule_net, rule_net4 },
		{ "net6", parse_rule_net, rule_net6 },
		{ NULL, NULL, 0 },
	};
	size_t i, adv;
	for (i = 0; match_table[i].name; i++) {
		if (strcmp(*fields, match_table[i].name) == 0) {
			adv = match_table[i].parser(++fields, --fieldnum, match_table[i].name, match_table[i].type);
			break;
		}
	}
	if (!match_table[i].name) {
		error("unknown matcher directive: %s", *fields);
	}
	fields += adv;
	fieldnum -= adv;

	static struct {
		char *name;
		int type;
		size_t (*parser)(char **, size_t, char *, int);
	} const proxy_table[] = {
		{ "deny", proxy_type_deny, parse_proxy_deny },
		{ "socks5", proxy_type_socks5, parse_proxy_hostname },
		// { "socks4a", proxy_type_socks4a, parse_proxy_socks4a },
		{ "unix-socks5", proxy_type_unix_socks5, parse_proxy_abs_path },
		{ "http-connect", proxy_type_http_connect, parse_proxy_hostname },
		{ NULL, 0, NULL },
	};
	proxy_cur = &proxy_begin;
	proxy_cur->next = NULL;
	while (*fields) {
		for (i = 0; proxy_table[i].name; i++) {
			if (strcmp(*fields, proxy_table[i].name) == 0) {
				adv = proxy_table[i].parser(++fields, --fieldnum, proxy_table[i].name, proxy_table[i].type);
				break;
			}
		}
		if (!proxy_table[i].name) {
			error("unknown proxy directive: %s", *fields);
		}
		fields += adv;
		fieldnum -= adv;
	}
	rule_cur->idx = lineno;
	rule_cur->proxy = proxy_begin.next;
}

void parse_rules(FILE *fp) {
	rule_cur = &rule_begin;
	size_t const buflen = 1024;
	char line[buflen];
	for (; fgets(line, buflen, fp); lineno++) {
		size_t linelen = strlen(line);
		if (linelen == buflen - 1 && line[linelen - 1] != '\n') {
			exit(2);
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
	rule_list = rule_begin.next;
}

void delete_rules(void) {
	while (rule_list) {
		switch (rule_list->type) {
		case rule_host:
			free(rule_list->u.host.name);
			break;
		case rule_net4:
			break;
		case rule_net6:
			break;
		}
		free(rule_list->ports);
		for (struct proxy *p = rule_list->proxy; p && p->type != proxy_type_deny; ) {
			switch (p->type) {
			case proxy_type_socks5:
			case proxy_type_http_connect:
				free(p->u.host_port.name);
				break;
			case proxy_type_unix_socks5:
				free(p->u.path);
				break;
			}
			struct proxy *np = p->next;
			free(p);
			p = np;
		}
		struct rule *nr = rule_list->next;
		free(rule_list);
		rule_list = nr;
	}
}

void load_rules(void) {
	if (!rule_path) return;
	FILE *rfp = fopen(rule_path, "r");
	if (!rfp) {
		perror("-r");
		exit(1);
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

struct rule *match_rule(char const *host, uint16_t port) {
	struct rule *rule = rule_list;

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
			{
				uint8_t addr[16];
				int addrtype;
				socklen_t addrlen;
				switch (rule->type) {
				case rule_net4:
					addrtype = AF_INET;
					addrlen = 4;
					break;
				case rule_net6:
					addrtype = AF_INET6;
					addrlen = 16;
					break;
				}
				pelog(LOG_DEBUG, "net in %s testcidr %d", host, rule->u.net.cidr);
				if (!inet_pton(addrtype, host, addr)) {
					break;
				}
				pelog(LOG_DEBUG, "net parse success");
				uint8_t *target = addr, *test = rule->u.net.addr;
				int mask = rule->u.net.cidr;

				while (mask >= 8) {
					if (*target++ != *test++) goto NEXT_RULE;
					mask -= 8;
				}
				int left = 8 - mask;
				if (mask && (*target >> left) != (*test >> left)) goto NEXT_RULE;
				if (match_port(port, rule->ports, rule->port_num)) return rule;
			}
			break;
		}
	NEXT_RULE:
		rule = rule->next;
	}
	return NULL;
}
