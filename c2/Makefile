CC     = gcc
CFLAGS = -Wall -Wextra -I.

SRCS = main.c icmp.c http.c dns.c
OBJS = $(SRCS:.c=.o)

all: c2 icmp_test

c2: $(OBJS)
	$(CC) $(CFLAGS) -o c2 $(OBJS)

icmp_test: icmp_test.c icmp.c
	$(CC) $(CFLAGS) -o icmp_test icmp_test.c icmp.c

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f c2 icmp_test $(OBJS)

.PHONY: all clean
