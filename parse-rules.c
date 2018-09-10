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

static bool simple_host_check(char const *host) {
	return !(*host == '-' || strstr(host, "..") || strstr(host, ".-") || strstr(host, "-.") || end_with(host, "-"));
}

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

static size_t parse_rule_host(char **fields, size_t fieldnum) {
	if (fieldnum < 1) {
		error("no arguments for host");
	}
	char *host = *fields++;
	fieldnum--;
	char *port = host;
	while (*port && *port != '#') {
		*port = tolower(*port);
		port++;
	}
	if (*port == '#') *port++ = '\0';
	if (!simple_host_check(host)) {
		error("invalid domain name: %s", host);
	}
	uint16_t *port_list;
	size_t port_num = parse_port(port, &port_list);
	rule_cur->next = calloc(1, sizeof(*rule_cur));
	rule_cur = rule_cur->next;
	rule_cur->type = rule_host;
	rule_cur->u.host.name = strdup(host);
	rule_cur->u.host.ports = port_list;
	rule_cur->u.host.port_num = port_num;
	return 1;
}

static void parse_fields(char **fields, size_t fieldnum) {
	static struct {
		char const *name;
		size_t (*parser)(char **, size_t);
	} const match_table[] = {
		{ "host", parse_rule_host },
		// { "net4", parse_rule_net4 },
		// { "net6", parse_rule_net6 },
		{ NULL, NULL },
	};
	size_t i, adv;
	for (i = 0; match_table[i].name; i++) {
		if (strcmp(*fields, match_table[i].name) == 0) {
			adv = match_table[i].parser(++fields, --fieldnum);
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
		{ "socks5", proxy_type_socks5, parse_proxy_hostname },
		{ "deny", proxy_type_deny, parse_proxy_deny },
		// { "socks4a", proxy_type_socks4a, parse_proxy_socks4a },
		// { "unix-socks5", proxy_type_unix_socks5, parse_proxy_unix_socks5 },
		// { "http-connect", proxy_type_http_connect, parse_proxy_http_connect },
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
	rule_cur->proxy = proxy_begin.next;
}

void parse_rules(FILE *fp) {
	rule_cur = &rule_begin;
	size_t const buflen = 1024;
	char line[buflen];
	while (fgets(line, buflen, fp)) {
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
