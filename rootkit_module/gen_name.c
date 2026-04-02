#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

static const char *prefixes[] = {
    "network", "system", "device", "kernel", "dbus",
    "udev",    "socket", "log",    "auth",   "sync",
    "acpi",    "input",  "power",  "disk",   "session",
    "user",    "time",   "locale", "resolve", "memory",
};

static const char *middles[] = {
    "helper", "manager", "handler", "monitor", "watcher",
    "agent",  "broker",  "proxy",   "relay",   "bridge",
    NULL,
};

static const char *suffixes[] = {
    "daemon",   "service", "manager", "helper",  "handler",
    "monitor",  "watcher", "agent",   "resolver", "listener",
};

#define N(arr) (sizeof(arr) / sizeof((arr)[0]))

static uint32_t rand_u32(void)
{
    uint32_t v;
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, &v, sizeof(v));
    close(fd);
    return v;
}

int main(void)
{
    const char *p = prefixes[rand_u32() % N(prefixes)];
    const char *m = middles [rand_u32() % N(middles)];
    const char *s = suffixes[rand_u32() % N(suffixes)];

    if (m)
        printf("%s-%s-%s\n", p, m, s);
    else
        printf("%s-%s\n", p, s);

    return 0;
}
