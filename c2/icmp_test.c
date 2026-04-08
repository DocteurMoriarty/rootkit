/*
 * icmp_test.c — ping 127.0.0.1 avec payload custom, affiche la réponse
 *
 * Usage : sudo ./icmp_test [ip]
 */

#include <stdio.h>
#include <string.h>
#include "icmp.h"

int main(int argc, char *argv[])
{
    icmp_ctx_t  ctx;
    uint8_t     payload[] = "hello icmp";
    uint8_t     reply[ICMP_PAYLOAD_MAX];
    char        src[INET_ADDRSTRLEN];
    const char *target = (argc > 1) ? argv[1] : "127.0.0.1";
    int         n;

    if (icmp_open(&ctx) != 0) {
        perror("icmp_open");
        return 1;
    }

    printf("[*] sending to %s : \"%s\"\n", target, (char *)payload);

    if (icmp_send(&ctx, target, payload, sizeof(payload) - 1) != 0) {
        perror("icmp_send");
        icmp_close(&ctx);
        return 1;
    }

    n = icmp_recv(&ctx, src, reply, sizeof(reply), 2000);
    if (n < 0) {
        fprintf(stderr, "[-] no reply (timeout or error)\n");
        icmp_close(&ctx);
        return 1;
    }

    reply[n] = '\0';
    printf("[+] reply from %s (%d bytes) : \"%s\"\n", src, n, (char *)reply);

    icmp_close(&ctx);
    return 0;
}
