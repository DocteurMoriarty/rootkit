#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"

int main() {

    struct rk_args args;

    int fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    // Envoyer un HELLO
    ioctl(fd, RK_CMD_HELLO, 0);

    // Demander l'UID courant
    ioctl(fd, RK_CMD_GETUID, &args);
    printf("UID courant : %u\n", args.target);

    args.target = (unsigned long)"I am Gr00t";
    args.value  = 0;
    ioctl(fd, RK_CMD_SET_MSG, &args);

    int rk = open("/tmp/.rk_cmd", O_RDWR | O_CREAT, 0644);
    char buf[256] = {0};
    read(rk, buf, sizeof(buf) - 1);
    printf("rk_cmd : %s\n", buf);
    close(rk);

    close(fd);
    return 0;
}
