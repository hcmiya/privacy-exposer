CC=c99
CFLAGS+=-D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_BSD_SOURCE
LDFLAGS+=-lpthread
SRCS=main.c common.c socks.c logger.c parse-rules.c worker.c greet-proxy.c
OBJS=$(SRCS:.c=.o)
HEADERS=privacy-exposer.h global.h

all: privacy-exposer

privacy-exposer: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm *.o privacy-exposer 2>/dev/null || :
