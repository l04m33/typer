/*
 * =====================================================================================
 *
 *       Filename:  usr_set.c
 *
 *    Description:  works with typer, to set the owner of the char device
 *
 *        Version:  0.1
 *        Created:  11/09/2008 08:09:14 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  l_amee (l_amee), l04m33@gmail.com
 *        Company:  SYSU
 *
 * =====================================================================================
 */

#include <linux/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "typer.h"

int main(int argc, char** argv)
{
    if(argc < 3){
        fprintf(stderr, "usage:\n    %s <file name> <uid>\n", argv[0]);
        exit(1);
    }

    int uid = atoi(argv[2]);
    int fd = open(argv[1], O_RDWR);
    if(fd < 0){
        perror("open");
        return fd;
    }
    fprintf(stderr, "ioctl=%d\n", ioctl(fd, TYPER_IOCSUSR, uid));
    perror("ioctl");
    fprintf(stderr, "uid=%d\n", ioctl(fd, TYPER_IOCGUSR));
    perror("ioctl");
    close(fd);
    return 0;
}
