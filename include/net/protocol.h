/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the protocol dispatcher.
 *
 * Version:	@(#)protocol.h	1.0.2	05/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Changes:
 *		Alan Cox	:	Added a name field and a frag handler
 *					field for later.
 *		Alan Cox	:	Cleaned up, and sorted types.
 *		Pedro Roque	:	inet6 protocols
 */
 
#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <linux/in6.h>
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#endif

#define MAX_INET_PROTOS	256		/* Must be a power of 2		*/

/*
net_protocol是一个非常重要的结构，定义了协议族中支持的传输层协议以及传输层的报文接收例程。
此结构是网络层和传输层之前的桥梁，当网络数据报文从网络层流向传输层时，
会调用此结构中的传输层协议数据报接收处理函数
*/
/* This is used to register protocols. */
struct net_protocol {

    //网络层根据ip协议字段的不同来调用不同的handler处理函数
    //例如协议字段为IPPROTO_ICMP 则handler对应icmp_rcv
	int			(*handler)(struct sk_buff *skb);

	//在ICMP模块中接收到差错报文后，会解析差错报文，并根据差错报文中原始的IP首部，
	//调用对应传输层的异常处理函数err_handler
	void			(*err_handler)(struct sk_buff *skb, u32 info);

	/*GSO是网络设备支持传输层的一个功能*/
	int			(*gso_send_check)(struct sk_buff *skb);
	
	struct sk_buff	       *(*gso_segment)(struct sk_buff *skb,
					       int features);

	struct sk_buff	      **(*gro_receive)(struct sk_buff **head,
					       struct sk_buff *skb);
	int			          (*gro_complete)(struct sk_buff *skb);
	
	unsigned int		no_policy:1,//此值为1 表示不需要进行IPsec策略检查(ip_local_deliver_finish中)
				        netns_ok:1; //此协议是否支持网络命名空间
};

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
struct inet6_protocol 
{
	int	(*handler)(struct sk_buff *skb);

	void	(*err_handler)(struct sk_buff *skb,
			       struct inet6_skb_parm *opt,
			       u8 type, u8 code, int offset,
			       __be32 info);

	int	(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff *(*gso_segment)(struct sk_buff *skb,
				       int features);
	struct sk_buff **(*gro_receive)(struct sk_buff **head,
					struct sk_buff *skb);
	int	(*gro_complete)(struct sk_buff *skb);

	unsigned int	flags;	/* INET6_PROTO_xxx */
};

#define INET6_PROTO_NOPOLICY	0x1
#define INET6_PROTO_FINAL	0x2
/* This should be set for any extension header which is compatible with GSO. */
#define INET6_PROTO_GSO_EXTHDR	0x4
#endif

/* This is used to register socket interfaces for IP protocols.  */
//将协议族操作集和具体协议操作集整合起来 inetsw_array
struct inet_protosw {
	struct list_head list;

        /* These two fields form the lookup key.  */
    /*
    标识套接口的类型，对于Internet协议族共有三种类型SOCK_STREAM、SOCK_DGRAM和SOCK_RAW，
    与应用程序层创建套接口函数socket()的第二个参数type取值对应
	*/
	unsigned short	 type;	   /* This is the 2nd argument to socket(2). */

   /*标识协议族中四层协议号，Internet协议族中的值包括IPPROTO_TCP、IPPROTO_UDP
   */ 		
	unsigned short	 protocol; /* This is the L4 protocol number.  */

    //传输层函数调用接口操作集TCP为tcp_prot;UDP为udp_prot;原始套接口raw_prot。
	struct proto	 *prot; //具体的协议操作集


	//inet层操作集合 TCP为inet_stream_ops;UDP为inet_dgram_ops;原始套接口inet_sockraw_ops
	const struct proto_ops *ops; //协议族操作集

    //当大于零时，需要检验当前创建套接口的进程是否有这种能力
	int              capability; /* Which (if any) capability do
				      * we need to use this socket
				      * interface?

                                    */
     //发送或接收报文时候是否需要校验和
	char             no_check;   /* checksum on rcv/xmit/none? */
	unsigned char	 flags;      /* See INET_PROTOSW_* below.  */
};
#define INET_PROTOSW_REUSE 0x01	     /* Are ports automatically reusable?  端口是否能重用*/
#define INET_PROTOSW_PERMANENT 0x02  /* Permanent protocols are unremovable. 标识端口是否能被重用标识此协议不能被替换或卸载*/
#define INET_PROTOSW_ICSK      0x04  /* Is this an inet_connection_sock? 标识是不是连接的套接口*/

extern const struct net_protocol *inet_protos[MAX_INET_PROTOS];

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern const struct inet6_protocol *inet6_protos[MAX_INET_PROTOS];
#endif

extern int	inet_add_protocol(const struct net_protocol *prot, unsigned char num);
extern int	inet_del_protocol(const struct net_protocol *prot, unsigned char num);
extern void	inet_register_protosw(struct inet_protosw *p);
extern void	inet_unregister_protosw(struct inet_protosw *p);

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern int	inet6_add_protocol(const struct inet6_protocol *prot, unsigned char num);
extern int	inet6_del_protocol(const struct inet6_protocol *prot, unsigned char num);
extern int	inet6_register_protosw(struct inet_protosw *p);
extern void	inet6_unregister_protosw(struct inet_protosw *p);
#endif

#endif	/* _PROTOCOL_H */
