/*
 * =====================================================================================
 *
 *       Filename:  replayer.c
 *
 *    Description:  replayer for typer
 *
 *        Version:  0.1
 *        Created:  11/08/2008 04:30:41 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  l_amee (l_amee), l04m33@gmail.com
 *        Company:  SYSU
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <linux/input.h>
#include <fcntl.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "typer.h"

int main(int argc, char **argv)
{
    struct __typer_ev tev;

    if(argc < 3){
        fprintf(stderr, "usage:\n  %s <src file> <dst file>\n", argv[0]);
        return 1;
    }

    int sf = open(argv[1], O_RDONLY);
    perror("open");
    if(sf < 0){
        return sf;
    }
    errno = 0;
    int df = open(argv[2], O_WRONLY);
    perror("open");
    if(df < 0){
        return df;
    }
    errno = 0;
    struct __typer_ev ev;
    printf("sizeof(ev)=%d\n", sizeof(ev));
    int ct = read(sf, &ev, sizeof(ev));
    while(ct == sizeof(struct __typer_ev)){
        printf("dev_type=%d, jiffies=%lu, type=%u, code=%u, value=%d\n", 
                ev.dev_type, ev.jiffies, ev.type, ev.code, ev.value);
        printf("wr=%d\n", write(df, &ev, sizeof(ev)));
        tev = ev;
        ct = read(sf, &ev, sizeof(ev));
    }

    // these are for the trailing ctrl+c stuff....

    tev.type = EV_KEY;
    tev.code = KEY_C;
    tev.value = 0;
    write(df, &tev, sizeof(tev));

    tev.code = KEY_LEFTCTRL;
    tev.value = 0;
    write(df, &tev, sizeof(tev));

    close(df);
    close(sf);

    return 0;
}

