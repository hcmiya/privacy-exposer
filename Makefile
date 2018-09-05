CFLAGS+=-D_POSIX_C_SOURCE=200809L
LDFLAGS+=-lpthread
SRCS=main.c common.c socks.c
OBJS=$(SRCS:.c=.o)
HEADERS=privacy-exposer.h global.h

all: privacy-exposer

privacy-exposer: $(OBJS)
	c99 -g $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

.c.o:
	c99 -g $(CFLAGS) -c $<

clean:
	rm *.o privacy-exposer 2>/dev/null || :
