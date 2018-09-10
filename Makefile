CFLAGS+=-D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_BSD_SOURCE
LDFLAGS+=-lpthread
SRCS=main.c common.c socks.c logger.c parse-rules.c
OBJS=$(SRCS:.c=.o)
HEADERS=privacy-exposer.h global.h

all: privacy-exposer

privacy-exposer: $(OBJS)
	c99 $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

.c.o:
	c99 $(CFLAGS) -c $<

clean:
	rm *.o privacy-exposer 2>/dev/null || :
