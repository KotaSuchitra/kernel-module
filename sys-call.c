// kprobe_open_logger.c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Suchitra");
MODULE_DESCRIPTION("Kprobe module that logs openat syscall invocations (safe unload)");

static struct kprobe kp;

/* Pre-handler: called just before the probed instruction executes */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    const char __user *user_path = (const char __user *)regs->si;
    char *kbuf;
    long copied;
    size_t bufsz = 256;

    kbuf = kmalloc(bufsz, GFP_ATOMIC);
    if (!kbuf)
        return 0;

    /* strncpy_from_user returns length (>=0) or negative on error */
    copied = strncpy_from_user(kbuf, user_path, bufsz - 1);
    if (copied > 0) {
        /* ensure null-terminated */
        if (copied >= bufsz) /* truncated */
            kbuf[bufsz - 1] = '\0';
        else
            kbuf[copied] = '\0';

        pr_info("[kprobe-open] pid=%d comm=%s path=\"%s\" flags=0x%lx\n",
                current->pid, current->comm, kbuf, (unsigned long)regs->dx);
    } else {
        pr_info("[kprobe-open] pid=%d comm=%s path=<user-read-failed> flags=0x%lx\n",
                current->pid, current->comm, (unsigned long)regs->dx);
    }

    kfree(kbuf);
    return 0;
}

/* Optional: post_handler or fault_handler could be added for more behavior */

static int __init kprobe_open_init(void)
{
    int ret;

    /* name of the kernel symbol to probe - adjust if your kernel uses different symbol */
    kp.symbol_name = "__x64_sys_openat";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    pr_info("kprobe_open_logger: registered kprobe at %s\n", kp.symbol_name);
    return 0;
}

static void __exit kprobe_open_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("kprobe_open_logger: unregistered kprobe from %s\n", kp.symbol_name);
}

module_init(kprobe_open_init);
module_exit(kprobe_open_exit);
