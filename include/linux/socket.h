#ifndef _LINUX_SOCKET_H
#define _LINUX_SOCKET_H

/*
 * Desired design of maximum size and alignment (see RFC2553)
 */
#define _K_SS_MAXSIZE	128	/* Implementation specific max size */
#define _K_SS_ALIGNSIZE	(__alignof__ (struct sockaddr *))
				/* Implementation specific desired alignment */

struct __kernel_sockaddr_storage {
	unsigned short	ss_family;		/* address family */
	/* Following field(s) are implementation specific */
	char		__data[_K_SS_MAXSIZE - sizeof(unsigned short)];
				/* space to achieve desired size, */
				/* _SS_MAXSIZE value minus size of ss_family */
} __attribute__ ((aligned(_K_SS_ALIGNSIZE)));	/* force desired alignment */

#ifdef __KERNEL__

#include <asm/socket.h>			/* arch-dependent defines	*/
#include <linux/sockios.h>		/* the SIOCxxx I/O controls	*/
#include <linux/uio.h>			/* iovec support		*/
#include <linux/types.h>		/* pid_t			*/
#include <linux/compiler.h>		/* __user			*/

#ifdef __KERNEL__
# ifdef CONFIG_PROC_FS
struct seq_file;
extern void socket_seq_show(struct seq_file *seq);
# endif
#endif /* __KERNEL__ */

typedef unsigned short	sa_family_t;

/*
 *	1003.1g requires sa_family_t and that sa_data is char.
 */
 
struct sockaddr {
	sa_family_t	sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
};


/*
1)l_onoff 等于0  关闭本选项,l_linger值被忽略,close立即返回
2)l_onoff 等于1  l_linger等于0, close某个连接时 终止一个连接发送RST 并丢弃发送缓冲区中内容
3)l_onoff 等于1  l_linger大于0, close不会立即返回 等到FIN的ACK在返回
*/
struct linger {
	int		l_onoff;	/* Linger active		是否关闭后等待的标志位*/
	int		l_linger;	/* How long to linger for	表示等待的时间*/
};

#define sockaddr_storage __kernel_sockaddr_storage

/*
 *	As we do 4.4BSD message passing we use a 4.4BSD message passing
 *	system, not 4.3. Thus msg_accrights(len) are now missing. They
 *	belong in an obscure libc emulation or the bin.
 */
 
struct msghdr {
	void	*	msg_name;	/* Socket name			名称 一般用NULL初始化 其实是对端的地址(当使用send的时候此值为NULL，使用sendto时候保存的地址)*/
	int		msg_namelen;	/* Length of name		上面名称的长度*/
	struct iovec *	msg_iov;	/* Data blocks			分散的数据块数组*/
	__kernel_size_t	msg_iovlen;	/* Number of blocks		分散的数据块个数*/
	void 	*	msg_control;	/* 控制信息  cmsghdr{}*/ 
	__kernel_size_t	msg_controllen;	/* 控制信息的长度*/
	unsigned	msg_flags;//传入的flag 如MSG_MORE
};

/*
 *	POSIX 1003.1g - ancillary data object information
 *	Ancillary data consits of a sequence of pairs of
 *	(cmsghdr, cmsg_data[])
 */

struct cmsghdr {
	__kernel_size_t	cmsg_len;	/* data byte count, including hdr 和CMSG_LEN()*/
        int		cmsg_level;	/* originating protocol */
        int		cmsg_type;	/* protocol-specific type */
};

/*
 *	Ancilliary data object information MACROS
 *	Table 5-14 of POSIX 1003.1g
 */
 /*
以下宏使用方式

for(cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr!= NULL;	cmsgptr=CMSG_NXTHDR(&msg,cmsgptr) )
{
	if(cmsgptr->cmsg_level == xxx  && cmsgptr->cmsg_type == xxx )
	{
		uchar *ptr;
		ptr = CMSG_DATA(cmsgptr);
		//deal data
	}
}

*/

#define __CMSG_NXTHDR(ctl, len, cmsg) __cmsg_nxthdr((ctl),(len),(cmsg))

//返回下一个cmsghdr{}结构指针 如已经没有了则返回NULL
#define CMSG_NXTHDR(mhdr, cmsg) cmsg_nxthdr((mhdr), (cmsg))

#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )

//指向域cmsghdr{}结构关联的数据的第一个字节
#define CMSG_DATA(cmsg)	((void *)((char *)(cmsg) + CMSG_ALIGN(sizeof(struct cmsghdr))))

//返回 给定数据长度下 一个辅助数据对象的总大小
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))

//返回给定数据长度下 msg_len中的值
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))

#define __CMSG_FIRSTHDR(ctl,len) ((len) >= sizeof(struct cmsghdr) ? \
				  (struct cmsghdr *)(ctl) : \
				  (struct cmsghdr *)NULL)

//返回第一个cmsghdr{} 结构的指针 若无辅助数据则返回NULL
#define CMSG_FIRSTHDR(msg)	__CMSG_FIRSTHDR((msg)->msg_control, (msg)->msg_controllen)
#define CMSG_OK(mhdr, cmsg) ((cmsg)->cmsg_len >= sizeof(struct cmsghdr) && \
			     (cmsg)->cmsg_len <= (unsigned long) \
			     ((mhdr)->msg_controllen - \
			      ((char *)(cmsg) - (char *)(mhdr)->msg_control)))

/*
 *	Get the next cmsg header
 *
 *	PLEASE, do not touch this function. If you think, that it is
 *	incorrect, grep kernel sources and think about consequences
 *	before trying to improve it.
 *
 *	Now it always returns valid, not truncated ancillary object
 *	HEADER. But caller still MUST check, that cmsg->cmsg_len is
 *	inside range, given by msg->msg_controllen before using
 *	ancillary object DATA.				--ANK (980731)
 */
 
static inline struct cmsghdr * __cmsg_nxthdr(void *__ctl, __kernel_size_t __size,
					       struct cmsghdr *__cmsg)
{
	struct cmsghdr * __ptr;

	__ptr = (struct cmsghdr*)(((unsigned char *) __cmsg) +  CMSG_ALIGN(__cmsg->cmsg_len));
	if ((unsigned long)((char*)(__ptr+1) - (char *) __ctl) > __size)
		return (struct cmsghdr *)0;

	return __ptr;
}

static inline struct cmsghdr * cmsg_nxthdr (struct msghdr *__msg, struct cmsghdr *__cmsg)
{
	return __cmsg_nxthdr(__msg->msg_control, __msg->msg_controllen, __cmsg);
}

/* "Socket"-level control message types: */

#define	SCM_RIGHTS	0x01		/* rw: access rights (array of int)  发送描述符*/
#define SCM_CREDENTIALS 0x02		/* rw: struct ucred		*/
#define SCM_SECURITY	0x03		/* rw: security label		*/

struct ucred {
	__u32	pid;
	__u32	uid;
	__u32	gid;
};

/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		  unix域套接字*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	  unix域套接字*/
#define AF_INET		2	/* Internet IP Protocol           ipv4协议	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			           ipv6协议*/
#define AF_ROSE		11	/* Amateur Radio X.25 PLP	*/
#define AF_DECnet	12	/* Reserved for DECnet project	*/
#define AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
#define AF_SECURITY	14	/* Security callback pseudo AF */
#define AF_KEY		15      /* PF_KEY key management API  密钥套接字 用于支持基于加密的安全性
                                     是内核中密钥表的接口*/
#define AF_NETLINK	16
#define AF_ROUTE	AF_NETLINK /* Alias to emulate 4.4BSD  路由套接字
                                                           内核中路由表的接口    
                                */
#define AF_PACKET	17	/* Packet family		*/
#define AF_ASH		18	/* Ash				*/
#define AF_ECONET	19	/* Acorn Econet			*/
#define AF_ATMSVC	20	/* ATM SVCs			*/
#define AF_RDS		21	/* RDS sockets  			*/
#define AF_SNA		22	/* Linux SNA Project (nutters!) */
#define AF_IRDA		23	/* IRDA sockets			*/
#define AF_PPPOX	24	/* PPPoX sockets		*/
#define AF_WANPIPE	25	/* Wanpipe API Sockets */
#define AF_LLC		26	/* Linux LLC			*/
#define AF_CAN		29	/* Controller Area Network      */
#define AF_TIPC		30	/* TIPC sockets			*/
#define AF_BLUETOOTH	31	/* Bluetooth sockets 		*/
#define AF_IUCV		32	/* IUCV sockets			*/
#define AF_RXRPC	33	/* RxRPC sockets 		*/
#define AF_ISDN		34	/* mISDN sockets 		*/
#define AF_PHONET	35	/* Phonet sockets		*/
#define AF_IEEE802154	36	/* IEEE802154 sockets		*/
#define AF_MAX		37	/* For now.. */

/* Protocol families, same as address families. */
#define PF_UNSPEC	AF_UNSPEC
#define PF_UNIX		AF_UNIX
#define PF_LOCAL	AF_LOCAL
#define PF_INET		AF_INET
#define PF_AX25		AF_AX25
#define PF_IPX		AF_IPX
#define PF_APPLETALK	AF_APPLETALK
#define	PF_NETROM	AF_NETROM
#define PF_BRIDGE	AF_BRIDGE
#define PF_ATMPVC	AF_ATMPVC
#define PF_X25		AF_X25
#define PF_INET6	AF_INET6
#define PF_ROSE		AF_ROSE
#define PF_DECnet	AF_DECnet
#define PF_NETBEUI	AF_NETBEUI
#define PF_SECURITY	AF_SECURITY
#define PF_KEY		AF_KEY
#define PF_NETLINK	AF_NETLINK
#define PF_ROUTE	AF_ROUTE
#define PF_PACKET	AF_PACKET//这个协议族允许应用程序直接从网络驱动器发送和接收数据包，这样就避开了协议栈操作 PF_PACKET协议族支持两种不同的套接字类型，SOCK_DGRAM和SOCK_RAW
                             //前者将去掉以太网头部再传输。后者给予应用程序完整的数据包
#define PF_ASH		AF_ASH
#define PF_ECONET	AF_ECONET
#define PF_ATMSVC	AF_ATMSVC
#define PF_RDS		AF_RDS
#define PF_SNA		AF_SNA
#define PF_IRDA		AF_IRDA
#define PF_PPPOX	AF_PPPOX
#define PF_WANPIPE	AF_WANPIPE
#define PF_LLC		AF_LLC
#define PF_CAN		AF_CAN
#define PF_TIPC		AF_TIPC
#define PF_BLUETOOTH	AF_BLUETOOTH
#define PF_IUCV		AF_IUCV
#define PF_RXRPC	AF_RXRPC
#define PF_ISDN		AF_ISDN
#define PF_PHONET	AF_PHONET
#define PF_IEEE802154	AF_IEEE802154
#define PF_MAX		AF_MAX

/* Maximum queue length specifiable by listen.  */
#define SOMAXCONN	128

/* Flags we can use with send/ and recv. 
   Added those for 1003.1g not all are supported yet
 */
 
#define MSG_OOB		1 //:指示接收到out-of-band数据(即需要优先处理的数据)
                      /*对于send本标志标明即将发送带外数据   对于recv标明 即将读入的带外数据
                        */
#define MSG_PEEK	2  //指示数据接收后，在接收队列中保留原数据，不将其删除，随后的读操作还可以接收相同的数据
                       //MSG_PEEK标志位会导致receive队列不会删除报文。所以，MSG_PEEK主要用于多进程读取同一套接字的情形
#define MSG_DONTROUTE	4  //绕过路由表查找 类似SO_DONTROUTE
#define MSG_TRYHARD     4       /* Synonym for MSG_DONTROUTE for DECnet */
#define MSG_CTRUNC	8 //指明由于缓冲区空间不足，一些控制数据已被丢弃
#define MSG_PROBE	0x10	/* 用户不想传输任何东西 而只是探测路径 */
#define MSG_TRUNC	0x20 //指明数据报尾部数据已被丢弃，因为它比所提供的缓冲区需要更多的空间

/*

临时将sockfd 设置为非阻塞模式,而无论原有是阻塞还是非阻塞。
recv(sockfd, buff, buff_size,MSG_DONTWAIT); //非阻塞模式的消息发送
send(scokfd, buff, buff_size, MSG_DONTWAIT); //非阻塞模式的消息接受
*/
#define MSG_DONTWAIT	0x40	/* Nonblocking io 单个操作临时设置为非阻塞 */

#define MSG_EOR         0x80	/* End of record指示记录的结束，返回的数据完成一个记录 */

                             //在读数据个数未满足前读操作不允许返回
                             /*
                                 1) 捕捉一个信号
                                 2) 连接终止
                                 3) 套接字发生错误
                                 以上三种情况 会导致读操作提前返回
                             */
#define MSG_WAITALL	0x100	/* Wait for a full request 要求阻塞操作，直到请求得到完整的满足。然而，如果捕捉到信号，错误或者连接断开发生，或者下次被接收的数据类型不同，仍会返回少于请求量的数据*/


#define MSG_FIN         0x200
#define MSG_SYN		0x400
#define MSG_CONFIRM	0x800	/* Confirm path validity */
#define MSG_RST		0x1000
#define MSG_ERRQUEUE	0x2000	/* Fetch message from error queue 指示除了来自套接字错误队列的错误外，没有接收到其它数据*/
/*
Linux 下当连接断开，还发送数据的时候，不仅 send() 的返回值会有反映，
而且还会向系统发送一个异常消息，如果不作处理，系统会出 BrokePipe，程序会退出，
这对于服务器提供稳定的服务将造成巨大的灾难。为此，
send() 函数的最后一个参数可以设置为 MSG_NOSIGNAL，禁止 send() 函数向系统发送异常消息
*/
#define MSG_NOSIGNAL	0x4000	/* Do not generate SIGPIPE */
#define MSG_MORE	0x8000	/* Sender will send more */

#define MSG_EOF         MSG_FIN //服务器在发送完应答消息后终止一个关联 那么可以在sctp_sndrcvinfo{}->_flags 设置此标志

#define MSG_CMSG_CLOEXEC 0x40000000	/* Set close_on_exit for file
					   descriptor received through
					   SCM_RIGHTS */
#if defined(CONFIG_COMPAT)
#define MSG_CMSG_COMPAT	0x80000000	/* This message needs 32 bit fixups */
#else
#define MSG_CMSG_COMPAT	0		/* We never have 32 bit fixups */
#endif


/* Setsockoptions(2) level. Thanks to BSD these must match IPPROTO_xxx */
#define SOL_IP		0
/* #define SOL_ICMP	1	No-no-no! Due to Linux :-) we cannot use SOL_ICMP=1 */
#define SOL_TCP		6
#define SOL_UDP		17
#define SOL_IPV6	41
#define SOL_ICMPV6	58
#define SOL_SCTP	132
#define SOL_UDPLITE	136     /* UDP-Lite (RFC 3828) */
#define SOL_RAW		255
#define SOL_IPX		256
#define SOL_AX25	257
#define SOL_ATALK	258
#define SOL_NETROM	259
#define SOL_ROSE	260
#define SOL_DECNET	261
#define	SOL_X25		262
#define SOL_PACKET	263
#define SOL_ATM		264	/* ATM layer (cell level) */
#define SOL_AAL		265	/* ATM Adaption Layer (packet level) */
#define SOL_IRDA        266
#define SOL_NETBEUI	267
#define SOL_LLC		268
#define SOL_DCCP	269
#define SOL_NETLINK	270
#define SOL_TIPC	271
#define SOL_RXRPC	272
#define SOL_PPPOL2TP	273
#define SOL_BLUETOOTH	274
#define SOL_PNPIPE	275
#define SOL_RDS		276
#define SOL_IUCV	277

/* IPX options */
#define IPX_TYPE	1

#ifdef __KERNEL__
extern int memcpy_fromiovec(unsigned char *kdata, struct iovec *iov, int len);
extern int memcpy_fromiovecend(unsigned char *kdata, const struct iovec *iov,
			       int offset, int len);
extern int csum_partial_copy_fromiovecend(unsigned char *kdata, 
					  struct iovec *iov, 
					  int offset, 
					  unsigned int len, __wsum *csump);

extern int verify_iovec(struct msghdr *m, struct iovec *iov, struct sockaddr *address, int mode);
extern int memcpy_toiovec(struct iovec *v, unsigned char *kdata, int len);
extern int memcpy_toiovecend(const struct iovec *v, unsigned char *kdata,
			     int offset, int len);
extern int move_addr_to_user(struct sockaddr *kaddr, int klen, void __user *uaddr, int __user *ulen);
extern int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr);
extern int put_cmsg(struct msghdr*, int level, int type, int len, void *data);

#endif
#endif /* not kernel and not glibc */
#endif /* _LINUX_SOCKET_H */
