#ifndef __ASM_GENERIC_SOCKIOS_H
#define __ASM_GENERIC_SOCKIOS_H

/* Socket-level I/O control calls. */

/*ioctl()  套接字选项*/ 
#define FIOSETOWN	0x8901       //设置本套接字的进程ID或进程组ID  int
#define SIOCSPGRP	0x8902       //设置本套接字的进程ID或进程组ID  int
#define FIOGETOWN	0x8903       //返回本套接字进程ID或进程组ID    int
#define SIOCGPGRP	0x8904       //返回本套接字进程ID或进程组ID    int
#define SIOCATMARK	0x8905       //是否位于带外标记  int  使用sockatmark()函数代替此ioctl选项
#define SIOCGSTAMP	0x8906		/* Get stamp (timeval) */
#define SIOCGSTAMPNS	0x8907		/* Get stamp (timespec) */

#endif /* __ASM_GENERIC_SOCKIOS_H */
