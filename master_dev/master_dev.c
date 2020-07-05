/* A master device driver using ksocket for sending files via TCP
 * BSD-style socket APIs for kernel 2.6 developers
 *
 * modified from a sample code:
 * https://github.com/hbagdi/ksocket/blob/master/sample/tcp/ksocket_tcp_srv_demo.c
 *
 * This code is licenced under the GPL
 * Feel free to contact me if any questions
 *
 * @2020
 * soyccan (soyccan@gmail.com)
 */
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/pfn.h>
#include <linux/printk.h>
#include <linux/socket.h>
#include <linux/string.h>

// the following must be included after <linux/*.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/uaccess.h>

#include "ksocket.h"
#include "master_dev.h"

#define MAX_CLIENT 10

// must < BLKDEV_MAJOR_MAX = 512, set to 0 for kernel to pick an used one
// may create a device by: mknod /dev/master c <major> <minor>
#define MASTER_DEV_MAJOR 64
#define MASTER_DEV_MINOR 3
#define MASTER_DEV_MINOR_COUNT 1
#define MASTER_DEV_NAME "master_dev"

// about log level:
// KERN_EMERG   /* system is unusable */
// KERN_ALERT   /* action must be taken immediately */
// KERN_CRIT    /* critical conditions */
// KERN_ERR     /* error conditions */
// KERN_WARNING /* warning conditions */
// KERN_NOTICE  /* normal but significant condition */
// KERN_INFO    /* informational */
// KERN_DEBUG   /* debug-level messages, require DEBUG be defined */
// KERN_DEFAULT /* the default kernel loglevel */
#define _pr_emerg(fmt, ...) pr_emerg("master_dev: " fmt "\n", ##__VA_ARGS__)
#define _pr_alert(fmt, ...) pr_alert("master_dev: " fmt "\n", ##__VA_ARGS__)
#define _pr_crit(fmt, ...) pr_crit("master_dev: " fmt "\n", ##__VA_ARGS__)
#define _pr_err(fmt, ...) pr_err("master_dev: " fmt "\n", ##__VA_ARGS__)
#define _pr_warning(fmt, ...) pr_warning("master_dev: " fmt "\n", ##__VA_ARGS__)
#define _pr_notice(fmt, ...) pr_notice("master_dev: " fmt "\n", ##__VA_ARGS__)
#define _pr_info(fmt, ...) pr_info("master_dev: " fmt "\n", ##__VA_ARGS__)
#define _pr_cont(fmt, ...) pr_cont("master_dev: " fmt "\n", ##__VA_ARGS__)
#define _pr_devel(fmt, ...) pr_devel("master_dev: " fmt "\n", ##__VA_ARGS__)
#define _pr_debug(fmt, ...) pr_debug("master_dev: " fmt "\n", ##__VA_ARGS__)

// virt_to_pfn() is not available on x86_64 when CONFIG_MMU is enabled.
// example:
// https://github.com/torvalds/linux/blob/master/drivers/infiniband/hw/hfi1/file_ops.c
// __pa() stands for physical address, equivalent to virt_to_phys()
#ifndef virt_to_pfn
#define virt_to_pfn(kaddr) PFN_DOWN(__pa(kaddr))
#endif



// file operations
static int master_mmap(struct file* file, struct vm_area_struct* vm_area);
static long master_ioctl(struct file* file,
                         unsigned int cmd,
                         unsigned long arg);
static ssize_t master_write(struct file* file,
                            const char __user* buf,
                            size_t count,
                            loff_t* offset);
static int master_open(struct inode* inode, struct file* file);
static int master_release(struct inode* inode, struct file* file);

static struct file_operations master_fops = {.owner = THIS_MODULE,
                                             .unlocked_ioctl = master_ioctl,
                                             .open = master_open,
                                             .write = master_write,
                                             .release = master_release,
                                             .mmap = master_mmap};


// module parameters
// module_param(name, type, sysfs permission);
// usage: insmod master.ko port=7777
static int port = 6666;
module_param(port, int, 0444);


// global variables
static ksocket_t sockfd_srv, sockfd_cli;
// static DEFINE_MUTEX(sockfd_cli_mutex);
static int open_cnt;
/* static struct task_struct* master_main_thread; */
static char* message_base;
static char* message;
#define MESSAGE_SIZE 4096

static struct cdev* master_dev;
static struct class* master_dev_class;
static dev_t master_devno;



/* send message in buffer via socket */
static long flush_message(int count)
{
    long ret;
    _pr_debug("flush message[:8]: %.8s count=%d", message, count);
    if ((ret = ksend(sockfd_cli, message, count, 0)) < 0) {
        _pr_alert("ksend failed ret=%ld", ret);
        return ret;
    }
    return 0;
}

static int master_mmap(struct file* file, struct vm_area_struct* vma)
{
    int ret;

    WARN_ON(virt_to_phys(message) != __pa(message));
    WARN_ON(virt_to_pfn(message) != __pa(message) >> PAGE_SHIFT);
    WARN_ON(PAGE_SHIFT != 12);
    _pr_debug("message: virt=0x%lx phys=0x%lx pfn=0x%lx", message,
              virt_to_phys(message), virt_to_pfn(message));

    // vma->vm_flags |= VM_IO; // TODO necessary?
    _pr_debug("mmap start=%lx size=%lu phys=%lx flag:VM_IO=%d", vma->vm_start,
              vma->vm_end - vma->vm_start, 0x878787UL, vma->vm_flags & VM_IO);

    // map an user space address (vm_start) to continuous frames
    // note that physical address that is mapped to is always aligned with
    // PAGE_SIZE
    if ((ret = remap_pfn_range(vma, vma->vm_start, virt_to_pfn(message),
                               vma->vm_end - vma->vm_start,
                               vma->vm_page_prot)) < 0) {
        _pr_alert("remap_pfn_range failed. ret=%d", ret);
        return ret;
    }

    return 0;
}

static long lookup_page_table(unsigned long address)
{
    pgd_t* pgd;
    p4d_t* p4d;
    pud_t* pud;
    pmd_t* pmd;
    pte_t *ptep, pte;

    pgd = pgd_offset(current->mm, address);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto page_lookup_fail;

    p4d = p4d_offset(pgd, address);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto page_lookup_fail;

    pud = pud_offset(p4d, address);
    if (pud_none(*pud) || pud_bad(*pud))
        goto page_lookup_fail;

    pmd = pmd_offset(pud, address);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto page_lookup_fail;

    ptep = pte_offset_kernel(pmd, address);
    if (!ptep)
        goto page_lookup_fail;

    pte = *ptep;
    _pr_info("mapped physical addr = 0x%lx,0x%p", pte, pte);
    return 0;

page_lookup_fail:
    _pr_alert("page lookup fail");
    return -EADDRNOTAVAIL;
}

static long accept_conn(void)
{
    char* tmp;
    struct sockaddr_in addr_cli = {0};

    if (sockfd_cli) {
        _pr_alert("an established connection already exists");
        return -EBUSY;
    }
    sockfd_cli = kaccept(sockfd_srv, (struct sockaddr*) &addr_cli, NULL);
    if (sockfd_cli == NULL) {
        _pr_alert("accept failed");
        return -ECONNREFUSED;
    }
    _pr_debug("sockfd_cli = 0x%p", sockfd_cli);

    tmp = inet_ntoa(&addr_cli.sin_addr);
    _pr_debug("got connected from : %s %d", tmp, ntohs(addr_cli.sin_port));
    kfree(tmp);

    return 0;
}

static long close_conn(void)
{
    int ret;

    _pr_debug("close connection");
    if (sockfd_cli == NULL) {
        _pr_alert("no established connection to close");
        return -ENXIO;
    }
    if ((ret = kclose(sockfd_cli)) < 0) {
        _pr_alert("kclose error, sockfd_cli=0x%p, ret=%d", sockfd_cli, ret);
        return ret;
    }
    sockfd_cli = NULL;

    return 0;
}

static long master_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
    int ret;

    if (cmd == MASTER_IOCTL_ACCEPT_CONN) {  // accept a connection
        return accept_conn();
    } else if (cmd == MASTER_IOCTL_CLOSE_CONN) {  // close connection
        return close_conn();
    } else if (cmd == MASTER_IOCTL_FLUSH) {
        // for mmap, flush message buffer after user finish writing
        return flush_message(arg);
    } else if (cmd == MASTER_IOCTL_GET_PHYS) {
        return lookup_page_table(arg);
    } else {
        return -ENOPROTOOPT;
    }
}

static ssize_t master_write(struct file* file,
                            const char __user* buf,
                            size_t count,
                            loff_t* offset)
{
    ssize_t ret;
    size_t written_size = 0;

    // TODO should we limit write size?
    // if (count >= MESSAGE_SIZE) {
    //     my_pr_warning("cannot write more than %d", MESSAGE_SIZE);
    //     return -EMSGSIZE;
    // }

    while (count > 0) {
        size_t msgsz = min(count, (size_t) MESSAGE_SIZE);
        if ((ret = copy_from_user(message, buf, msgsz)) < 0) {
            _pr_alert("copy_from_user failed ret=%ld", ret);
            return ret;
        }

        count -= msgsz;
        written_size += msgsz;
        buf += msgsz;
        // _pr_debug("got write message=%.5s msgsz=%d remain count=%d",
        // message, msgsz, count);

        flush_message(msgsz);
    }
    return written_size;
}

static int master_open(struct inode* inode, struct file* file)
{
    if (open_cnt > 0) {
        _pr_alert("device busy");
        return -EBUSY;
    }
    open_cnt++;

    // module reference count to prevent unexpected `rmmod`
    try_module_get(THIS_MODULE);

    _pr_debug("open");

    return 0;
}

static int master_release(struct inode* inode, struct file* file)
{
    open_cnt--;
    module_put(THIS_MODULE);
    _pr_debug("close");
    return 0;
}

// static int master_main_run(void* arg) {}

static char* master_devnode(struct device* dev, umode_t* mode)
{
    // https://github.com/torvalds/linux/blob/v4.6/drivers/tty/tty_io.c
    if (!mode)
        return NULL;
    *mode = 0666;
    return NULL;
}


static int __init master_init(void)
{
    int ret;
    struct sockaddr_in addr_srv = {0};

    _pr_debug("master init");

    // obtain an unused device number
    // if ((ret = alloc_chrdev_region(&master_devno, MASTER_DEV_MINOR,
    //                                MASTER_DEV_MINOR_COUNT, MASTER_DEV_NAME))
    //                                < 0) {
    //     _pr_alert("alloc_chrdev_region failed ret=%d", ret);
    //     return ret;
    // }
    // or regester a specific device number
    master_devno = MKDEV(MASTER_DEV_MAJOR, MASTER_DEV_MINOR);
    if ((ret = register_chrdev_region(master_devno, MASTER_DEV_MINOR_COUNT,
                                      MASTER_DEV_NAME)) < 0) {
        _pr_alert("register_chrdev_region failed ret=%d", ret);
        return ret;
    }

    // register character device
    if ((master_dev = cdev_alloc()) == NULL) {
        _pr_alert("cdev_alloc failed");
        return -ENOMEM;
    }
    cdev_init(master_dev, &master_fops);
    master_dev->owner = THIS_MODULE;
    if ((ret = cdev_add(master_dev, master_devno, 1)) < 0) {
        _pr_alert("cdev_add failed");
        return ret;
    }

    // create class and device in sysfs
    master_dev_class = class_create(THIS_MODULE, MASTER_DEV_NAME "_class");
    if (IS_ERR(master_dev_class)) {
        _pr_alert("create class master_dev_clas failed. ret=%ld",
                  master_dev_class);
        return PTR_ERR(master_dev_class);
    }
    master_dev_class->devnode = master_devnode;
    device_create(master_dev_class, NULL, master_devno, NULL, MASTER_DEV_NAME);

    // start a thread to avoid blocking socket read
    /* master_main_thread = */
    /*     kthread_run(master_main_run, NULL, "master_main_thread"); */

    // for user-mode function call like open()/write() to work,
    // we should adjust memory limit
    /* mm_segment_t old_fs; */
    /* old_fs = get_fs(); */
    /* set_fs(KERNEL_DS); */

    // `message` should be aligned with PAGE_SIZE
    message_base = kmalloc(2 * PAGE_SIZE, GFP_KERNEL);
    message =
        (char*) (((unsigned long) message_base + PAGE_SIZE - 1) & PAGE_MASK);
    WARN_ON((unsigned long) message & ~PAGE_MASK);  // warn if not aligned
    _pr_debug("kmalloc message_base=%lx message=%lx", message_base, message);

    // start server
    sockfd_srv = sockfd_cli = NULL;
    addr_srv.sin_family = AF_INET;
    addr_srv.sin_port = htons(port);
    addr_srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // addr_srv.sin_addr.s_addr = INADDR_ANY;

    sockfd_srv = ksocket(AF_INET, SOCK_STREAM, 0);
    _pr_debug("sockfd_srv = 0x%p", sockfd_srv);
    if (sockfd_srv == NULL) {
        _pr_alert("socket failed");
        return -ENOTCONN;
    }
    if ((ret = kbind(sockfd_srv, (struct sockaddr*) &addr_srv,
                     sizeof(addr_srv))) < 0) {
        _pr_alert("bind failed: sockfd_srv=%p addr=%s:%d ret=%d", sockfd_srv,
                  inet_ntoa(&addr_srv.sin_addr), ntohs(addr_srv.sin_port), ret);
        return ret;
    }
    if ((ret = klisten(sockfd_srv, MAX_CLIENT)) < 0) {
        _pr_alert("listen failed: ret=%d", ret);
        return ret;
    }

    /* set_fs(old_fs); */

    _pr_debug("master init success");
    return 0;
}

static void __exit master_exit(void)
{
    int ret;

    _pr_debug("master exit");

    if (sockfd_srv) {
        if ((ret = kclose(sockfd_srv)) < 0) {
            _pr_alert("kclose error, sockfd_srv=0x%p, ret=%d", sockfd_srv, ret);
        }
        sockfd_srv = NULL;
    }

    kfree(message_base);
    message_base = message = NULL;

    device_destroy(master_dev_class, master_devno);
    class_destroy(master_dev_class);
    // TODO kfree(master_dev_class) ? seems no
    master_dev_class = NULL;

    cdev_del(master_dev);
    kfree(master_dev);
    master_dev = NULL;

    unregister_chrdev_region(master_devno, MASTER_DEV_MINOR_COUNT);

    // TODO this causes problem on rmmod
    // kthread_stop(master_main_thread);
}

module_init(master_init);
module_exit(master_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("soyccan");
MODULE_DESCRIPTION("Junk master device");
