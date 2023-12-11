#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/sched/task_stack.h>
#include <asm/syscall.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/security.h>
#include <linux/string.h>

struct socket_info
{
    int fd;
    int state;
    int type;
    unsigned long flags;
};

struct socket_count_message
{
    int count;
};

struct sockets_info_message
{
    int count;
    struct socket_info *sockets;
};

struct context_len_message
{
    int len;
};

struct context_info_message
{
    int maxlen;
    char *str;
};

struct ioctl_message
{
    pid_t pid;
    bool err;
    union
    {
        struct socket_count_message socket_count_m;
        struct sockets_info_message sockets_info_m;
        struct context_len_message context_len_m;
        struct context_info_message context_info_m;
    };
};

#define WR_SOCKET_COUNT _IOW('a', 2, struct ioctl_message *)
#define WR_SOCKET_INFO _IOW('a', 3, struct ioctl_message *)
#define WR_CONTEXT_LEN _IOW('a', 4, struct ioctl_message *)
#define WR_CONTEXT_INFO _IOW('a', 5, struct ioctl_message *)

/*Meta information*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("wieceslaw");
MODULE_DESCRIPTION("Linux kernel driver (IOCTL)");
MODULE_VERSION("1.0");

int __init etx_driver_init(void);
void __exit etx_driver_exit(void);
long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int etx_open(struct inode *inode, struct file *file);
int etx_release(struct inode *inode, struct file *file);
ssize_t etx_read(struct file *filp, char __user *buf, size_t len, loff_t *off);
ssize_t etx_write(struct file *filp, const char *buf, size_t len, loff_t *off);

struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = etx_read,
    .write = etx_write,
    .open = etx_open,
    .unlocked_ioctl = etx_ioctl,
    .release = etx_release,
};

dev_t dev = 0;
struct class *dev_class;
struct cdev etx_cdev;

int fill_socket_count(int pid, struct socket_count_message *msg)
{
    int err = 0;
    struct task_struct *task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    struct fdtable *files_table = files_fdtable(task->files);
    int i = 0, count = 0;
    while (files_table->fd[i] != NULL)
    {
        struct file *fl = files_table->fd[i];
        if (S_ISSOCK(fl->f_path.dentry->d_inode->i_mode))
        {
            pr_info("Open socket with fd %d \n", i);
            count++;
        }
        i++;
    }
    msg->count = count;
    return err;
}

int fill_sockets_info(int pid, struct sockets_info_message *sockets_info)
{
    struct task_struct *task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (task == NULL)
    {
        return 1;
    }

    struct fdtable *files_table = files_fdtable(task->files);
    int i = 0, count = 0;
    while (files_table->fd[i] != NULL)
    {
        struct file *fl = files_table->fd[i];
        if (S_ISSOCK(fl->f_path.dentry->d_inode->i_mode))
        {
            pr_info("Open socket with fd %d \n", i);
            struct socket *sock = sock_from_file(fl);
            if (sock)
            {
                struct socket_info *info = sockets_info->sockets + count;
                info->fd = i;
                info->state = sock->state;
                info->type = sock->type;
                info->flags = sock->flags;
            }
            else
            {
                pr_err("Error retrieve socket \n");
                return 1;
            }
            count++;
            if (count == sockets_info->count)
            {
                return 0;
            }
        }
        i++;
    }
    return 0;
}

int task_lsm_context(int pid, struct lsmcontext *ctx)
{
    struct task_struct *task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (task == NULL)
    {
        return 1;
    }
    struct lsmblob blob;
    security_task_getsecid_obj(task, &blob);
    pr_info("SECID: %d \n", blob.secid[0]);
    int err = security_secid_to_secctx(&blob, ctx, 0);
    if (err)
    {
        pr_err("CTX ERR: %d \n", err);
        return 1;
    }
    return 0;
}

int fill_context_len(int pid, struct context_len_message *msg)
{
    struct lsmcontext ctx;
    int err = task_lsm_context(pid, &ctx);
    if (err)
    {
        return err;
    }
    msg->len = ctx.len;
    return 0;
}

int fill_context_info(int pid, struct context_info_message *msg)
{
    struct lsmcontext ctx;
    int err = task_lsm_context(pid, &ctx);
    if (err)
    {
        return err;
    }
    memcpy(msg->str, ctx.context, msg->maxlen + 1);
    return 0;
}

// Main function to control read/write
long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct ioctl_message *message = (struct ioctl_message *)arg;
    pr_info("IOCTL PID=%d\n", message->pid);
    switch (cmd)
    {
    case WR_SOCKET_COUNT:
    {
        message->err = fill_socket_count(message->pid, &(message->socket_count_m));
        if (!message->err)
        {
            pr_info("SOCKETS COUNT %d \n", message->socket_count_m.count);
        }
        else
        {
            pr_err("SOCKETS COUNT ERR \n");
        }
        break;
    }
    case WR_SOCKET_INFO:
    {
        pr_info("SOCKETS INFO \n");
        message->err = fill_sockets_info(message->pid, &(message->sockets_info_m));
        break;
    }
    case WR_CONTEXT_LEN:
    {
        pr_info("CONTEXT LEN \n");
        message->err = fill_context_len(message->pid, &(message->context_len_m));
        break;
    }
    case WR_CONTEXT_INFO:
    {
        pr_info("CONTEXT INFO \n");
        message->err = fill_context_info(message->pid, &(message->context_info_m));
        break;
    }
    default:
    {
        pr_info("Default \n");
        break;
    }
    }
    return 1;
}

int __init etx_driver_init(void)
{
    /*Allocating Major number*/
    if ((alloc_chrdev_region(&dev, 0, 1, "etx_Dev")) < 0)
    {
        pr_err("Cannot allocate major number \n");
        return -1;
    }
    pr_info("Major = %d Minor = %d \n", MAJOR(dev), MINOR(dev));

    /*Creating cdev structure*/
    cdev_init(&etx_cdev, &fops);

    /*Adding character device to the system*/
    if ((cdev_add(&etx_cdev, dev, 1)) < 0)
    {
        pr_err("Cannot add the device to the system \n");
        goto r_class;
    }

    /*Creating struct class*/
    if ((dev_class = class_create(THIS_MODULE, "etx_class")) == NULL)
    {
        pr_err("Cannot create the struct class \n");
        goto r_class;
    }

    /*Creating device*/
    if ((device_create(dev_class, NULL, dev, NULL, "etx_device")) == NULL)
    {
        pr_err("Cannot create the Device 1 \n");
        goto r_device;
    }
    pr_info("Device Driver Insert...Done \n");
    return 0;

r_device:
    class_destroy(dev_class);
r_class:
    unregister_chrdev_region(dev, 1);
    return -1;
}

// Function on deleting module
void __exit etx_driver_exit(void)
{
    device_destroy(dev_class, dev);
    class_destroy(dev_class);
    cdev_del(&etx_cdev);
    unregister_chrdev_region(dev, 1);
    pr_info("Device Driver Remove...! \n");
    pr_info("Done \n");
}

/* This function will be called when we open the Device file */
int etx_open(struct inode *inode, struct file *file)
{
    pr_info("Device File Opened... \n");
    return 0;
}

/* This function will be called when we close the Device file */
int etx_release(struct inode *inode, struct file *file)
{
    pr_info("Device File Closed... \n");
    return 0;
}

/* This function will be called when we read the Device file */
ssize_t etx_read(struct file *filp, char __user

                                        *buf,
                 size_t len, loff_t *off)
{
    pr_info("Read Function \n");
    return 0;
}

/* This function will be called when we write the Device file */
ssize_t etx_write(struct file *filp, const char __user

                                         *buf,
                  size_t len, loff_t *off)
{
    pr_info("Write function \n");
    return len;
}

module_init(etx_driver_init);
module_exit(etx_driver_exit);
