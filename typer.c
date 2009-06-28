/*
 * =======================================================================
 *
 *       Filename:  typer.c
 *
 *    Description:  An input stream dumper & simulator
 *
 *        Version:  0.1
 *        Created:  11/07/2008 08:32:59 PM
 *       Compiler:  gcc
 *
 *         Author:  Kay Zheng (l_amee), l04m33@gmail.com
 *
 * =======================================================================
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include "typer.h"


#ifdef TYPER_DEBUG
#define PDBG(fmt, args...) printk(KERN_DEBUG "typer: " fmt, ## args)
#else
#define PDBG(fmt, args...) /* empty PDBG slot */
#endif

#define TYPER_PERR(fmt, args...) printk(KERN_NOTICE "typer: " fmt, ## args)
#define TYPER_PINFO(fmt, args...) printk(KERN_NOTICE "typer: " fmt, ## args)


/* functions */
static void typer_event(
        struct input_handle *handle, 
        unsigned int event_type,
        unsigned int event_code, 
        int value
        );

static int typer_connect(
        struct input_handler *handler, 
        struct input_dev *dev,
        const struct input_device_id *id
        );

static void typer_disconnect(struct input_handle *handle);

int typer_open(struct inode *inode, struct file *file);

int typer_release(struct inode *inode, struct file *file);

ssize_t typer_read(struct file *file, char __user *buf, 
                   size_t count, loff_t *pos);

ssize_t typer_write(struct file *file, const char __user *buf,
                    size_t count, loff_t *pos);

int typer_ioctl(struct inode *inode, struct file *filp, 
                unsigned int cmd, unsigned long arg);

/* used by typer_write, ripped from input.c */
static inline int is_event_supported(unsigned int code,
                                     unsigned long *bm, unsigned int max)
{
	return code <= max && test_bit(code, bm);
}

static int  __init typer_init(void);
static void __exit typer_exit(void);
module_init(typer_init);
module_exit(typer_exit);

MODULE_LICENSE("GPL");



/* globals */
/* module parameters */
static char* kbd_name = "Keyboard";
static char* mouse_name = "Mouse";
module_param(kbd_name, charp, S_IRUGO);
module_param(mouse_name, charp, S_IRUGO);

unsigned long typer_user = 0;
unsigned long old_jiffies = 0;

struct input_handle *kbd_handle = 0;
struct input_handle *mouse_handle = 0;
struct device typer_dev;

atomic_t typer_count = ATOMIC_INIT(0); /* open count */

DECLARE_WAIT_QUEUE_HEAD(typer_wq);
LIST_HEAD(typer_ev_list);              /* event list */
spinlock_t typer_ev_lock = SPIN_LOCK_UNLOCKED; /* event list lock */

static dev_t typer_devno;
static struct cdev typer_cdev;
struct file_operations typer_fops = {
    .open    = typer_open,
    .release = typer_release,
    .read    = typer_read,
    .write   = typer_write,
    .ioctl   = typer_ioctl,
    .owner   = THIS_MODULE,
};

/* ID tables below are ripped from keyboard.c & mousedev.c 
 * from kernel tree.
 */

static const struct input_device_id typer_kbd_ids[] = {
    /*
     * keyboard ids
     */
    { 
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT,
        .evbit = { BIT_MASK(EV_KEY) },
    },
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT,
        .evbit = { BIT_MASK(EV_SND) },
    },
    {}, /* Terminating item */
};

MODULE_DEVICE_TABLE(input, typer_kbd_ids);

static const struct input_device_id typer_mouse_ids[] = {
    /*
     * mouse ids
     */
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT |
                INPUT_DEVICE_ID_MATCH_KEYBIT |
                INPUT_DEVICE_ID_MATCH_RELBIT,
        .evbit = { BIT_MASK(EV_KEY) | BIT_MASK(EV_REL) },
        .keybit = { [BIT_WORD(BTN_LEFT)] = BIT_MASK(BTN_LEFT) },
        .relbit = { BIT_MASK(REL_X) | BIT_MASK(REL_Y) },
    },  /* A mouse like device, at least one button,
            two relative axes */
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT |
                INPUT_DEVICE_ID_MATCH_RELBIT,
        .evbit = { BIT_MASK(EV_KEY) | BIT_MASK(EV_REL) },
        .relbit = { BIT_MASK(REL_WHEEL) },
    },  /* A separate scrollwheel */
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT |
                INPUT_DEVICE_ID_MATCH_KEYBIT |
                INPUT_DEVICE_ID_MATCH_ABSBIT,
        .evbit = { BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS) },
        .keybit = { [BIT_WORD(BTN_TOUCH)] = BIT_MASK(BTN_TOUCH) },
        .absbit = { BIT_MASK(ABS_X) | BIT_MASK(ABS_Y) },
    },	/* A tablet like device, at least touch detection,
            two absolute axes */
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT |
                INPUT_DEVICE_ID_MATCH_KEYBIT |
                INPUT_DEVICE_ID_MATCH_ABSBIT,
        .evbit = { BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS) },
        .keybit = { [BIT_WORD(BTN_TOOL_FINGER)] =
                BIT_MASK(BTN_TOOL_FINGER) },
        .absbit = { BIT_MASK(ABS_X) | BIT_MASK(ABS_Y) |
                BIT_MASK(ABS_PRESSURE) |
                BIT_MASK(ABS_TOOL_WIDTH) },
    },	/* A touchpad */
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT |
                INPUT_DEVICE_ID_MATCH_KEYBIT |
                INPUT_DEVICE_ID_MATCH_ABSBIT,
        .evbit = { BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS) },
        .keybit = { [BIT_WORD(BTN_LEFT)] = BIT_MASK(BTN_LEFT) },
        .absbit = { BIT_MASK(ABS_X) | BIT_MASK(ABS_Y) },
    },	/* Mouse-like device with absolute X and Y but ordinary
            clicks, like hp ILO2 High Performance mouse */

    { }, /* Terminating entry */
};

MODULE_DEVICE_TABLE(input, typer_mouse_ids);

static struct input_handler typer_kbd_handler = {
    .event      = typer_event,
    .connect    = typer_connect,
    .disconnect = typer_disconnect,
    .name       = "typer_kbd",
    .id_table   = typer_kbd_ids,
    /* exclude devices that may be recognised as a mouse */
    .blacklist  = typer_mouse_ids,
};

static struct input_handler typer_mouse_handler = {
    .event      = typer_event,
    .connect    = typer_connect,
    .disconnect = typer_disconnect,
    .name       = "typer_mouse",
    .id_table   = typer_mouse_ids,
};



/* codes */
static void typer_event(
        struct input_handle *handle, 
        unsigned int event_type,
        unsigned int event_code, 
        int value
        )
{
    /* 0) Forward the event to the hooked handle.
     * 1) Check if there's a process waiting for events.
     * 2) If true, push the event into the event queue, else return ASAP.
     * 3) Wake the waiting processes.
     *
     * Since some of the devices may have been grabbed by someone, 
     * we need a hook on that handle to retrieve events.
     *
     * And, this function is called with the device-wide * event_lock 
     * held, it's in atomic context.
     */

    struct typer_ev *ev;
    struct input_handle *ev_owner, *grab;
    long   count; 
    unsigned long flags;

    //PDBG("event: handle=%s, type=%u, code=%u, value=%d\n", 
    //     handle->name, event_type, event_code, value);

    rcu_read_lock();
	grab = rcu_dereference(handle->dev->grab);
    ev_owner = handle->private;
    if(ev_owner && (grab == handle))
        ev_owner->handler->event(ev_owner, event_type, event_code, value);
    rcu_read_unlock();

    count = atomic_read(&typer_count);
    if(!count) return;

    /* keep kmalloc() from sleeping */
    if(!(ev = kmalloc(sizeof(struct typer_ev), GFP_ATOMIC))){
        TYPER_PERR("Memory allocation for typer_event failed.\n");
        return;
    }
    
    if(handle->handler == &typer_kbd_handler)
        ev->rev.dev_type = TYPER_DEV_KBD;
    else if(handle->handler == &typer_mouse_handler)
        ev->rev.dev_type = TYPER_DEV_MOUSE;
    else{
        /* something's wrong if we'll ever reach this */
        TYPER_PERR("Event for unknown device recieved, ignore.\n");
        kfree(ev);
        return;
    }
    ev->rev.type = event_type;
    ev->rev.code = event_code;
    ev->rev.value = value;
    ev->rev.jiffies = jiffies;

    spin_lock_irqsave(&typer_ev_lock, flags);
    list_add_tail(&ev->list, &typer_ev_list); 
    spin_unlock_irqrestore(&typer_ev_lock, flags);

    wake_up_interruptible(&typer_wq);
}

static int typer_connect(
        struct input_handler *handler, 
        struct input_dev *dev,
        const struct input_device_id *id
        )
{
    /* 0) Find kbd_handle & mouse_handle from dev's handle list.
     * 1) Hook the input device, if it's grabbed.
     * 2) Input_register_handle()
     * 3) Input_open_device()
     */

    /* XXX: The hooking for mouse doesn't work when a device is 
     *      hotplugged, because the X server grabs a device *after* 
     *      this function is run.
     */

    int ret;
    struct input_handle *grab, *handle;

    /* we want a handle from keyboard or mouse to inject events */
    ret = mutex_lock_interruptible(&dev->mutex);
    if(ret) return ret;
    if(handler == &typer_kbd_handler){
        /* XXX: It's ugly to judge from the device names, but I don't 
         *      have a better solution, yet. 
         */
        if(strstr(dev->name, kbd_name))
            /* The first handle is good, we want it. */
            kbd_handle = list_entry(dev->h_list.next, 
                                    struct input_handle, d_node);
        else{
            mutex_unlock(&dev->mutex);
            return -ENODEV;
        }
    }else if(handler == &typer_mouse_handler){
        if(strstr(dev->name, mouse_name))
            mouse_handle = list_entry(dev->h_list.next, 
                                      struct input_handle, d_node);
        else{
            mutex_unlock(&dev->mutex);
            return -ENODEV;
        }
    }else{
        mutex_unlock(&dev->mutex);
        return -ENODEV;
    }
    mutex_unlock(&dev->mutex);

    PDBG("Attaching to device=%s, handler=%s\n", dev->name, handler->name);

    handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
    if(handle == NULL) return -ENOMEM;
    handle->dev = dev;
    handle->handler = handler;
    handle->name = handler->name;

    rcu_read_lock();
    grab = rcu_dereference(dev->grab);
    if(grab){
        PDBG("    Device grabbed, handle name: %s\n", grab->name);
        handle->private = grab;  /* hook the grabbed handle */
        rcu_read_unlock();
	    rcu_assign_pointer(dev->grab, handle);
	    synchronize_rcu();
    }else{
        handle->private = NULL;
        rcu_read_unlock();
    }

    ret = input_register_handle(handle);
    if(ret) goto free_handle;

    ret = input_open_device(handle);
    if(ret) goto unreg_handle;

    return 0;

unreg_handle:
    input_unregister_handle(handle);
free_handle:
    kfree(handle);
    return ret;
}

static void typer_disconnect(struct input_handle *handle)
{
    struct input_handle *grab;

    /* restore the hooked handle */
    rcu_read_lock();
    grab = rcu_dereference(handle->dev->grab);
    if(grab == handle){
        rcu_read_unlock();
	    rcu_assign_pointer(handle->dev->grab, handle->private);
	    synchronize_rcu();
    }else{
        rcu_read_unlock();
    }

    /*XXX: er...if you have multiple keyboards (or mice), pulling 
     * one of them out will disable the module (you won't be able 
     * to 'replay' any more, but event recording still works fine)
     */

    /* wipe out kbd_handle & mouse_handle acordingly */
    if(strstr(handle->dev->name, kbd_name))
        kbd_handle = NULL;
    else if(strstr(handle->dev->name, mouse_name))
        mouse_handle = NULL;

	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static int __init typer_init(void)
{
    /* 0) Register char device.
     * 1) Register input handler.
     */
    int err;

    err = alloc_chrdev_region(&typer_devno, 0, 1, "typer");
    if(err){
        TYPER_PERR("Error allocating char device region, abort.\n");
        return err;
    }

    TYPER_PINFO("using devno: major=%d, minor=%d\n", 
                MAJOR(typer_devno), MINOR(typer_devno));

    cdev_init(&typer_cdev, &typer_fops);
    typer_cdev.owner = THIS_MODULE;
    err = cdev_add(&typer_cdev, typer_devno, 1);
    if(err){
        TYPER_PERR("Error adding char device, abort.\n");
        goto unreg_cdev_rgn;
    }

    err = input_register_handler(&typer_kbd_handler);
    if(err){
        TYPER_PERR("Failed to register keyboard handler, abort.\n");
        goto del_cdev;
    }
    err = input_register_handler(&typer_mouse_handler);
    if(err){
        TYPER_PERR("Failed to register mouse handler, abort.\n");
        goto unreg_kbd;
    }

    snprintf(typer_dev.bus_id, sizeof(typer_dev.bus_id), "typer");
    typer_dev.devt = typer_devno;
    typer_dev.class = &input_class;
    typer_dev.parent = NULL;
    typer_dev.release = NULL;
	device_initialize(&typer_dev);

    err = device_add(&typer_dev);
    if(err){
        TYPER_PERR("Failed to register device, abort.\n");
        goto unreg_mouse;
    }

    return 0;

unreg_mouse:
    input_unregister_handler(&typer_mouse_handler);
unreg_kbd:
    input_unregister_handler(&typer_kbd_handler);
del_cdev:
    cdev_del(&typer_cdev);
unreg_cdev_rgn:
    unregister_chrdev_region(typer_devno, 1);
    return err;
}

static void __exit typer_exit(void)
{
    /* 0) Unregister input handler.
     * 1) Unregister char device.
     * 2) Cleanup the event list.
     */

    struct typer_ev *ev, *tmp;

    device_del(&typer_dev);
    input_unregister_handler(&typer_mouse_handler);
    input_unregister_handler(&typer_kbd_handler);
    cdev_del(&typer_cdev);
    unregister_chrdev_region(typer_devno, 1);

    /* We have only one event list, clean it up here 
     * (and in typer_release()).
     * Since nobody's able to access typer_ev_list now, we don't 
     * need any locks.
     */
    list_for_each_entry_safe(ev, tmp, &typer_ev_list, list){
        list_del(&ev->list);
        kfree(ev);
    }
}


int typer_open(struct inode *inode, struct file *file)
{
    /* !!! We only check user rights in typer_open(), if 
     * the program dropped the privilege after openning the file,
     * it can still read & write.
     */
    if((current->uid != typer_user) && !capable(CAP_SYS_ADMIN))
        return -EPERM;
    if(atomic_inc_return(&typer_count) != 1){
        atomic_dec(&typer_count);
        return -EBUSY;
    }
    return 0;
}

int typer_release(struct inode *inode, struct file *file)
{
    struct typer_ev *ev, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&typer_ev_lock, flags);
    if(!list_empty(&typer_ev_list))
        list_for_each_entry_safe(ev, tmp, &typer_ev_list, list){
            list_del(&ev->list);
            kfree(ev);
        }
    spin_unlock_irqrestore(&typer_ev_lock, flags);

    old_jiffies = 0;
    atomic_dec(&typer_count);
    return 0;
}

ssize_t typer_read(struct file *file, char __user *buf, 
                   size_t count, loff_t *pos)
{
    /* 0) Check the event queue.
     * 1) Wait on empty queue.
     * 2) Push events to user space.
     */

    struct typer_ev *ev, *tmp;
    char *ptr;
    size_t unit_sz = sizeof(struct __typer_ev);
    unsigned long flags;

    spin_lock_irqsave(&typer_ev_lock, flags);
    while(list_empty(&typer_ev_list)){
        spin_unlock_irqrestore(&typer_ev_lock, flags);
        /* respect the no-blocking flag */
        if(file->f_flags & O_NONBLOCK) return -EAGAIN;  
        if(wait_event_interruptible(typer_wq, !list_empty(&typer_ev_list)))
            return -ERESTARTSYS;
        spin_lock_irqsave(&typer_ev_lock, flags);
    }

    ptr = buf;
    ev = list_entry(typer_ev_list.next, struct typer_ev, list);
    while((count >= unit_sz) && !list_empty(&typer_ev_list)){
        spin_unlock_irqrestore(&typer_ev_lock, flags);
        if(copy_to_user(ptr, &ev->rev, unit_sz))
            return -EFAULT;
        ptr += unit_sz;
        count -= unit_sz;
        spin_lock_irqsave(&typer_ev_lock, flags);
        tmp = list_entry(ev->list.next, struct typer_ev, list);
        list_del(&ev->list);
        kfree(ev);
        ev = tmp;
    }
    spin_unlock_irqrestore(&typer_ev_lock, flags);

    return ptr-buf;
}

ssize_t typer_write(struct file *file, const char __user *buf,
                    size_t count, loff_t *pos)
{
    /* 0) Check the events' insanity (XXX: partially done).
     * 1) Post the events to devices.
     *
     * Writing to typer never blocks.
     */

    struct __typer_ev ev;
    size_t unit_sz = sizeof(struct __typer_ev);
    unsigned long flags, delta;
    const char *ptr = buf;

    if(count < unit_sz)
        return -EINVAL;

    while(count >= unit_sz){
        if(copy_from_user(&ev, ptr, unit_sz))
            return -EFAULT;

        if(!old_jiffies)
            old_jiffies = ev.jiffies;
        delta = ev.jiffies - old_jiffies;
        if(delta){
            /* better do this in user space? */
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(delta);
        }
        old_jiffies = ev.jiffies;

        /*XXX: One event at a time may lag the system. */
        if(ev.dev_type == TYPER_DEV_KBD){
	        if ((kbd_handle != NULL) && 
                is_event_supported(ev.type, kbd_handle->dev->evbit, 
                                   EV_MAX)) {
                spin_lock_irqsave(&(kbd_handle->dev->event_lock), flags);
                kbd_handle->handler->event(kbd_handle, ev.type, 
                                           ev.code, ev.value);
                spin_unlock_irqrestore(&(kbd_handle->dev->event_lock),
                                       flags);
            }
        }else if(ev.dev_type == TYPER_DEV_MOUSE){
	        if ((mouse_handle != NULL) && 
                is_event_supported(ev.type, mouse_handle->dev->evbit, 
                                   EV_MAX)) {
                spin_lock_irqsave(&(mouse_handle->dev->event_lock), flags);
                mouse_handle->handler->event(mouse_handle, ev.type, 
                                             ev.code, ev.value);
                spin_unlock_irqrestore(&(mouse_handle->dev->event_lock), 
                                       flags);
            }
        }else{
            TYPER_PERR("Got event from unknown device, ignore.\n");
        }

        count -= unit_sz;
        ptr += unit_sz;
    }

    return ptr - buf;
}

int typer_ioctl(struct inode *inode, struct file *filp,
                unsigned int cmd, unsigned long arg)
{
    /* only usable by root */
    if(!capable(CAP_SYS_ADMIN))
        return -EPERM;

    switch(cmd){
        case TYPER_IOCSUSR:
            typer_user = arg;
            return 0;
        case TYPER_IOCGUSR:
            return typer_user;
    }

    return -EINVAL;
}

