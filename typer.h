/*
 * =======================================================================
 *
 *       Filename:  typer.h
 *
 *    Description:  describe data structures & constants used by typer
 *
 *        Version:  0.1
 *        Created:  11/09/2008 11:50:18 PM
 *       Compiler:  gcc
 *
 *         Author:  Kay Zheng (l_amee), l04m33@gmail.com
 *
 * =======================================================================
 */

#ifndef __TYPER_H__
#define __TYPER_H__

#include <linux/ioctl.h>
#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/list.h>
#endif


#define TYPER_IOC_MAGIC '9'
#define TYPER_IOCSUSR _IOW(TYPER_IOC_MAGIC, 1, unsigned long)
#define TYPER_IOCGUSR _IOR(TYPER_IOC_MAGIC, 2, unsigned long)

/* structures */
struct __typer_ev {
    __u32 dev_type;  /* use __u32 to get aligned on 4-byte boundry */
#define TYPER_DEV_UNKNOWN 0
#define TYPER_DEV_KBD 1
#define TYPER_DEV_MOUSE 2
    unsigned long jiffies;
    __u16 type;
    __u16 code;
    __u32 value;
}__attribute((packed));

#ifdef __KERNEL__
struct typer_ev {
    struct __typer_ev rev;
    struct list_head list;
}__attribute__((packed));
#endif

#endif /* __TYPER_H__ */

