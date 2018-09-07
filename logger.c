#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>

#include "privacy-exposer.h"
#include "global.h"

static int level = LOG_DEBUG;

static void pelog_not_syslog(int priority, char const *fmt, ...) {
	if (priority > level) return;

	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}

static void pelog_not_syslog_th(int priority, char const *fmt, ...) {
	if (priority > level) return;

	struct petls *tls = pthread_getspecific(sock_cleaner);
	printf("%s %s: %ldms: ", tls->id, tls->reqhost, lapse_ms(&tls->btime));

	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}

static void vpelog_not_syslog(int priority, char const *fmt, va_list ap) {
	if (priority > level) return;
	va_list copyap;
	va_copy(copyap, ap);
	vprintf(fmt, copyap);
	va_end(copyap);
	putchar('\n');
}

static void pelog_syslog_th(int priority, char const *fmt, ...) {
	struct petls *tls = pthread_getspecific(sock_cleaner);

	char fmt_with_id[512];
	sprintf(fmt_with_id, "%s %s: %ldms: %s", tls->id, tls->reqhost, lapse_ms(&tls->btime), fmt);

	va_list ap;
	va_start(ap, fmt);
	vsyslog(priority, fmt_with_id, ap);
	va_end(ap);
}

void pelog_open(bool use_syslog, int loglevel) {
	if (use_syslog) {
		openlog("privacy-exposer", 0, LOG_USER);
		int const tab[] = {
			LOG_EMERG,  LOG_ALERT,  LOG_CRIT,  LOG_ERR,  LOG_WARNING,  LOG_NOTICE,  LOG_INFO, LOG_DEBUG
		};
		int logmask = 0;
		for (int i = 0; i <= loglevel; i++) {
			logmask |= LOG_MASK(tab[i]);
		}
		setlogmask(logmask);
		pelog = syslog;
		pelog_th = pelog_syslog_th;
		vpelog = vsyslog;
	}
	else {
		level = loglevel;
		pelog = pelog_not_syslog;
		pelog_th = pelog_not_syslog_th;
		vpelog = vpelog_not_syslog;
	}
}

