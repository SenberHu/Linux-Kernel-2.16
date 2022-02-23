/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions of the Internet Protocol.
 *
 * Version:	@(#)in.h	1.0.1	04/21/93
 *
 * Authors:	Original taken from the GNU Project <netinet/in.h> file.
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_IN_H
#define _LINUX_IN_H

#include <linux/types.h>
#include <linux/socket.h>

/* Standard well-defined IP protocols.  */
enum {
  IPPROTO_IP = 0,		/* Dummy protocol for TCP		*/
  IPPROTO_ICMP = 1,		/* Internet Control Message Protocol	*/
  IPPROTO_IGMP = 2,		/* Internet Group Management Protocol	*/
  IPPROTO_IPIP = 4,		/* IPIP tunnels (older KA9Q tunnels use 94)   */
  IPPROTO_TCP = 6,		/* Transmission Control Protocol	          TCP传输协议*/
  IPPROTO_EGP = 8,		/* Exterior Gateway Protocol		*/
  IPPROTO_PUP = 12,		/* PUP protocol				*/
  IPPROTO_UDP = 17,		/* User Datagram Protocol		              UDP传输协议*/
  IPPROTO_IDP = 22,		/* XNS IDP protocol			*/
  IPPROTO_DCCP = 33,		/* Datagram Congestion Control Protocol */
  IPPROTO_RSVP = 46,		/* RSVP protocol			*/
  IPPROTO_GRE = 47,		/* Cisco GRE tunnels (rfc 1701,1702)	*/

  IPPROTO_IPV6	 = 41,		/* IPv6-in-IPv4 tunnelling		*/

                                        
  IPPROTO_ESP = 50,            /* ESP协议 Encapsulation Security Payload protocol 
                                  ESP会为每个数据包添加新的报头和报尾  
                                 */
  /*
     ESP格式
       *******************************
       *         spi                 *
       *******************************
       *       序列号SN              *
       *******************************
       *       有效负载数据          * 
       *******************************
       *      填充(0~255)            *
       *            填充长度|下一报头*
       *******************************
       *      身份验证数据           * 
       *******************************
       SPI:32的安全索引 与原地址一起来标志SA
       SN: 长32位 每传输一个数据包就加1
       有效负载数据:经过加密的数据块
       填充:填充加密的数据块 使其满足对齐要求
       填充长度: 长1字节 表示填充部分的长度
       下一报头: 长1字节 指出下一个报头的类型
       身份验证数据:完整性检查值
  */
    
  IPPROTO_AH = 51,             /* Authentication Header protocol       */
  IPPROTO_BEETPH = 94,	       /* IP option pseudo header for BEET */
  IPPROTO_PIM    = 103,		/* Protocol Independent Multicast	*/

  IPPROTO_COMP   = 108,                /* Compression Header protocol */
  IPPROTO_SCTP   = 132,		/* Stream Control Transport Protocol	   SCTP传输协议*/
  IPPROTO_UDPLITE = 136,	/* UDP-Lite (RFC 3828)			*/

  IPPROTO_RAW	 = 255,		/* Raw IP packets			*/
  IPPROTO_MAX
};

//in_addr和下面的sockaddr_in 结构是标准的网络接口地址结构定义
/* Internet address. */
struct in_addr {
	__be32	s_addr;
};


/*IPPROTO_IP  setsockopt(2)*/
#define IP_TOS		1   //设置 ip首部的服务类型 (int)  IPTOS_LOWDELAY
#define IP_TTL		2   //存活时间 (int)

#define IP_HDRINCL	3  //IPPROTO_IP 本选项给一个原始套接字设置 我们必须自己给数据包构造ip头
                       /*下列情况 内核会自己填写一些ip字段
                          ip校验和
                          如果我们设置ip标致为0  内核将设置该字段
                          若源ip为INADDR_ANY 内核将填写出口ip
                          
                         */ 
#define IP_OPTIONS	4  //ip首部选项 

#define IP_ROUTER_ALERT	5 //路由器警告
#define IP_RECVOPTS	6
#define IP_RETOPTS	7
#define IP_PKTINFO	8
#define IP_PKTOPTIONS	9
#define IP_MTU_DISCOVER	10
#define IP_RECVERR	11
#define IP_RECVTTL	12
#define	IP_RECVTOS	13
#define IP_MTU		14
#define IP_FREEBIND	15
#define IP_IPSEC_POLICY	16
#define IP_XFRM_POLICY	17
#define IP_PASSSEC	18
#define IP_TRANSPARENT	19

/* BSD compatibility */
#define IP_RECVRETOPTS	IP_RETOPTS

/* TProxy original addresses */
#define IP_ORIGDSTADDR       20
#define IP_RECVORIGDSTADDR   IP_ORIGDSTADDR

//路径MTU发现是用来确定到达目的地的路径中最大传输单元(MTU)的大小
/* IP_MTU_DISCOVER values */
#define IP_PMTUDISC_DONT		0	/* Never send DF frames 从不设置DF位，即不进行PMTU发现*/
#define IP_PMTUDISC_WANT		1	/* Use per route hints	策略根据路由中表项是否锁定了MTU，来决定是否设置DF位，如锁定，不设置DF位*/
#define IP_PMTUDISC_DO			2	/* Always DF		策略总是设置DF位，除非内核设置了忽略df（ignore_df）*/
#define IP_PMTUDISC_PROBE		3       /* Ignore dst pmtu      */

#define IP_MULTICAST_IF			32//获取默认接口或设置接口  in_addr{}
#define IP_MULTICAST_TTL 		33//设置多播组数据的TTL值 (u_char) 
#define IP_MULTICAST_LOOP 		34//禁止组播数据回送     (u_char) 
#define IP_ADD_MEMBERSHIP		35//用于把一个本地的IP地址加入到一个多播组  ip_mreq{}
#define IP_DROP_MEMBERSHIP		36//退出组播组 ip_mreq{}
#define IP_UNBLOCK_SOURCE		37//开通多播源  ip_mreq_source{}
#define IP_BLOCK_SOURCE			38 //阻塞多博源 ip_mreq_source{}
#define IP_ADD_SOURCE_MEMBERSHIP	39 //加入源特定多播组 ip_mreq_source{}
#define IP_DROP_SOURCE_MEMBERSHIP	40 //离开源特定多播组 ip_mreq_source{}
#define IP_MSFILTER			41 
#define MCAST_JOIN_GROUP		42
#define MCAST_BLOCK_SOURCE		43
#define MCAST_UNBLOCK_SOURCE		44
#define MCAST_LEAVE_GROUP		45
#define MCAST_JOIN_SOURCE_GROUP		46
#define MCAST_LEAVE_SOURCE_GROUP	47
#define MCAST_MSFILTER			48
#define IP_MULTICAST_ALL		49

#define MCAST_EXCLUDE	0
#define MCAST_INCLUDE	1

/* These need to appear somewhere around here */
#define IP_DEFAULT_MULTICAST_TTL        1
#define IP_DEFAULT_MULTICAST_LOOP       1

/* Request struct for multicast socket ops */
//对多播地址或其对应的网络接口进行设置或获取
struct ip_mreq 
{
	struct in_addr imr_multiaddr;	/* IP multicast address of group */
	struct in_addr imr_interface;	/* local IP address of interface */
};

struct ip_mreqn
{
	struct in_addr	imr_multiaddr;		/*多播组的IP地址*/ /* IP multicast address of group */
	struct in_addr	imr_address;		/*本地址网络接口的IP地址*/ /* local IP address of interface */
	int		imr_ifindex;		/*网络接口序号*//* Interface index */
};

struct ip_mreq_source {
	__be32		imr_multiaddr;
	__be32		imr_interface;
	__be32		imr_sourceaddr;
};

struct ip_msfilter {
	__be32		imsf_multiaddr;
	__be32		imsf_interface;
	__u32		imsf_fmode;
	__u32		imsf_numsrc;
	__be32		imsf_slist[1];
};

#define IP_MSFILTER_SIZE(numsrc) \
	(sizeof(struct ip_msfilter) - sizeof(__u32) \
	+ (numsrc) * sizeof(__u32))

struct group_req
{
	__u32				 gr_interface;	/* interface index */
	struct __kernel_sockaddr_storage gr_group;	/* group address */
};

struct group_source_req
{
	__u32				 gsr_interface;	/* interface index */
	struct __kernel_sockaddr_storage gsr_group;	/* group address */
	struct __kernel_sockaddr_storage gsr_source;	/* source address */
};

struct group_filter
{
	__u32				 gf_interface;	/* interface index */
	struct __kernel_sockaddr_storage gf_group;	/* multicast address */
	__u32				 gf_fmode;	/* filter mode */
	__u32				 gf_numsrc;	/* number of sources */
	struct __kernel_sockaddr_storage gf_slist[1];	/* interface index */
};

#define GROUP_FILTER_SIZE(numsrc) \
	(sizeof(struct group_filter) - sizeof(struct __kernel_sockaddr_storage) \
	+ (numsrc) * sizeof(struct __kernel_sockaddr_storage))

struct in_pktinfo
{
	int		ipi_ifindex;
	struct in_addr	ipi_spec_dst;
	struct in_addr	ipi_addr;
};

/* Structure describing an Internet (IP) socket address. */
#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/

struct sockaddr_in {
  sa_family_t		sin_family;	                  /* Address family		*/
  __be16		    sin_port;	                  /* Port number			*/
  struct in_addr	sin_addr;	                  /* Internet address		*/

  /* Pad to size of `struct sockaddr'. */
  unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
			sizeof(unsigned short int) - sizeof(struct in_addr)];
};
#define sin_zero	__pad		/* for BSD UNIX comp. -FvK	*/


/*
 * Definitions of the bits in an Internet address integer.
 * On subnets, host and network parts are found according
 * to the subnet mask, not these masks.
 */
 //A类地址 0~127 2^7=256个网络地址 0和127(本地回环地址)保留 每个网络2^24个主机
 //掩码为255.0.0.0
#define	IN_CLASSA(a)		((((long int) (a)) & 0x80000000) == 0)
#define	IN_CLASSA_NET		0xff000000
#define	IN_CLASSA_NSHIFT	24
#define	IN_CLASSA_HOST		(0xffffffff & ~IN_CLASSA_NET)
#define	IN_CLASSA_MAX		128

//B类地址:128~191 每个网络地址对应2^16个主机地址 掩码:255.255.0.0
#define	IN_CLASSB(a)		((((long int) (a)) & 0xc0000000) == 0x80000000)
#define	IN_CLASSB_NET		0xffff0000
#define	IN_CLASSB_NSHIFT	16
#define	IN_CLASSB_HOST		(0xffffffff & ~IN_CLASSB_NET)
#define	IN_CLASSB_MAX		65536

//c类地址192~223 每个网络地址对应2^8个主机地址  掩码255.255.255.0 
#define	IN_CLASSC(a)		((((long int) (a)) & 0xe0000000) == 0xc0000000)
#define	IN_CLASSC_NET		0xffffff00
#define	IN_CLASSC_NSHIFT	8
#define	IN_CLASSC_HOST		(0xffffffff & ~IN_CLASSC_NET)

//D类地址 范围224~247
#define	IN_CLASSD(a)		((((long int) (a)) & 0xf0000000) == 0xe0000000)
#define	IN_MULTICAST(a)		IN_CLASSD(a)
#define IN_MULTICAST_NET	0xF0000000

#define	IN_EXPERIMENTAL(a)	((((long int) (a)) & 0xf0000000) == 0xf0000000)
#define	IN_BADCLASS(a)		IN_EXPERIMENTAL((a))

/* Address to accept any incoming messages. */
#define	INADDR_ANY		((unsigned long int) 0x00000000)

/* Address to send to all hosts. */
#define	INADDR_BROADCAST	((unsigned long int) 0xffffffff)

/* Address indicating an error return. */
#define	INADDR_NONE		((unsigned long int) 0xffffffff)

/* Network number for local host loopback. */
#define	IN_LOOPBACKNET		127

/* Address to loopback in software to local host.  */
#define	INADDR_LOOPBACK		0x7f000001	/* 127.0.0.1   */
#define	IN_LOOPBACK(a)		((((long int) (a)) & 0xff000000) == 0x7f000000)

/* Defines for Multicast INADDR */
#define INADDR_UNSPEC_GROUP   	0xe0000000U	/* 224.0.0.0   */
#define INADDR_ALLHOSTS_GROUP 	0xe0000001U	/* 224.0.0.1   */
#define INADDR_ALLRTRS_GROUP    0xe0000002U	/* 224.0.0.2 */
#define INADDR_MAX_LOCAL_GROUP  0xe00000ffU	/* 224.0.0.255 */


/* <asm/byteorder.h> contains the htonl type stuff.. */
#include <asm/byteorder.h> 

#ifdef __KERNEL__

static inline bool ipv4_is_loopback(__be32 addr)
{
	return (addr & htonl(0xff000000)) == htonl(0x7f000000);
}

static inline bool ipv4_is_multicast(__be32 addr)
{
	return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
}

static inline bool ipv4_is_local_multicast(__be32 addr)
{
	return (addr & htonl(0xffffff00)) == htonl(0xe0000000);
}

static inline bool ipv4_is_lbcast(__be32 addr)
{
	/* limited broadcast */
	return addr == htonl(INADDR_BROADCAST);
}

static inline bool ipv4_is_zeronet(__be32 addr)
{
	return (addr & htonl(0xff000000)) == htonl(0x00000000);
}

/* Special-Use IPv4 Addresses (RFC3330) */

static inline bool ipv4_is_private_10(__be32 addr)
{
	return (addr & htonl(0xff000000)) == htonl(0x0a000000);
}

static inline bool ipv4_is_private_172(__be32 addr)
{
	return (addr & htonl(0xfff00000)) == htonl(0xac100000);
}

static inline bool ipv4_is_private_192(__be32 addr)
{
	return (addr & htonl(0xffff0000)) == htonl(0xc0a80000);
}

static inline bool ipv4_is_linklocal_169(__be32 addr)
{
	return (addr & htonl(0xffff0000)) == htonl(0xa9fe0000);
}

static inline bool ipv4_is_anycast_6to4(__be32 addr)
{
	return (addr & htonl(0xffffff00)) == htonl(0xc0586300);
}

static inline bool ipv4_is_test_192(__be32 addr)
{
	return (addr & htonl(0xffffff00)) == htonl(0xc0000200);
}

static inline bool ipv4_is_test_198(__be32 addr)
{
	return (addr & htonl(0xfffe0000)) == htonl(0xc6120000);
}
#endif

#endif	/* _LINUX_IN_H */
