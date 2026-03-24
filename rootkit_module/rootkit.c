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
    .name  = "rootkit",
    .fops  = &rk_fops,
};

static int __init init(void)
{
    int ret;

    ret = misc_register(&rk_misc);
    if (ret) {
        printk(KERN_ERR "rootkit: misc_register failed (%d)\n", ret);
        return ret;
    }

    printk(KERN_INFO "rootkit: loaded — /dev/rootkit (minor=%d)\n",
           rk_misc.minor);
    return 0;
}

static void __exit exit(void)
{
    misc_deregister(&rk_misc);
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(init);
module_exit(exit);
