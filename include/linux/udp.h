/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the UDP protocol.
 *
 * Version:	@(#)udp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_UDP_H
#define _LINUX_UDP_H

#include <linux/types.h>

struct udphdr {
	__be16	source;//发送端端口号
	__be16	dest; //接收端端口号
	__be16	len; //长度 UDP首部+数据部分
	__sum16	check; //校验和
};

/* UDP socket options */
#define UDP_CORK	1	/* Never send partially complete segments, udp抑制功能
                           在这个选项启用的时候套接字输出的所有数据都将累计为一个数据报,等这个选项取消后 再进行传输
                           禁用 启用这个套接字选项使用系统调用setsockopt*/
#define UDP_ENCAP	100	/* Set the socket to accept encapsulated packets */

/* UDP encapsulation types */
#define UDP_ENCAP_ESPINUDP_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define UDP_ENCAP_ESPINUDP	2 /* draft-ietf-ipsec-udp-encaps-06 */
#define UDP_ENCAP_L2TPINUDP	3 /* rfc2661 */

#ifdef __KERNEL__
#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <net/netns/hash.h>

static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}

#define UDP_HTABLE_SIZE		128

static inline int udp_hashfn(struct net *net, const unsigned num)
{
	return (num + net_hash_mix(net)) & (UDP_HTABLE_SIZE - 1);
}

struct udp_sock {
	/* inet_sock has to be the first member */
	struct inet_sock inet;
	int		 pending;	/* Any pending frames ? */
	unsigned int	 corkflag;	/* Cork is required UDP抑制功能 看UDP_CORK
                                   这个标志只会对套接字设置一次 然后一直有效
                                   直到显示的被关闭
                                   MSG_MORE 标志可以在每次传输时单独设定或清除
	                               */
  	__u16		 encap_type;	/* Is this an Encapsulation socket? */
	/*
	 * Following member retains the information to create a UDP header
	 * when the socket is uncorked.
	 */
	__u16		 len;		/* total length of pending frames */
	/*
	 * Fields specific to UDP-Lite.
	 */
	__u16		 pcslen;
	__u16		 pcrlen;
/* indicator bits used by pcflag: */
#define UDPLITE_BIT      0x1  		/* set by udplite proto init function */
#define UDPLITE_SEND_CC  0x2  		/* set via udplite setsockopt         */
#define UDPLITE_RECV_CC  0x4		/* set via udplite setsocktopt        */
	__u8		 pcflag;        /* marks socket as UDP-Lite if > 0    */
	__u8		 unused[3];
	/*
	 * For encapsulation sockets.
	 */
	int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);
};

static inline struct udp_sock *udp_sk(const struct sock *sk)
{
	return (struct udp_sock *)sk;
}

#define IS_UDPLITE(__sk) (udp_sk(__sk)->pcflag)

#endif

#endif	/* _LINUX_UDP_H */
