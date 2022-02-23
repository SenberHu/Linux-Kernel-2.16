/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 * 		Arnaldo Carvalho de Melo <acme@mandriva.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_SOCK_H
#define _INET_SOCK_H


#include <linux/kmemcheck.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/jhash.h>

#include <net/flow.h>
#include <net/sock.h>
#include <net/request_sock.h>
#include <net/netns/hash.h>

/** struct ip_options - IP Options
 *
 * @faddr -   Saved first hop address
 * @is_data - Options in __data, rather than skb
 * @is_strictroute - Strict source route
 * @srr_is_hit -  Packet destination addr was our one
 * @is_changed -  IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {
	__be32		faddr;//存储第一跳的地址 方法ip_options_compile 将在处理 宽松或严格路由选择时设置这个成员
	unsigned char	optlen;//以字节为单位的选项长度 不能超过40字节
	unsigned char	srr;//一个报头中只能出现一个源路由(松散或严格) 标志已经解析过一个,源路由存在的位置相对与ip报头
	unsigned char	rr; //记录路由数据起始的偏移量相对与ip报头
	unsigned char	ts;//时间戳数据相对与ip报头存在的起始位置
	unsigned char	is_strictroute:1,//是否为严格源路由 在ip_options_compile分析严格源路由时设置
			srr_is_hit:1,//目标地址为本机标志
			is_changed:1,//ip校验和不在有效 只要有ip选项发生变化 就会设置此标志
			rr_needaddr:1,//需要记录外出的ip地址 针对记录路由来设置此标志
			ts_needtime:1,//设置时间戳选项 并且标志位 为IPOPT_TS_TSONLY  IPOPT_TS_TSANDADDR IPOPT_TS_PRESPEC 设置此值为1
			ts_needaddr:1;//仅设置了时间戳选项 并且标志为  IPOPT_TS_TSANDADDR
	unsigned char	router_alert;//在ip_options_compile 分析路由警告信息后 设置此标志
	unsigned char	cipso;
	unsigned char	__pad2;
	unsigned char	__data[0];//一个缓冲区 用于存储setsockopt从用户空间获得的选项
};

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct inet_request_sock 
{
	struct request_sock	req;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	u16			inet6_rsk_offset;
#endif

	__be16			loc_port; /* 服务器端端口号 */
	__be32			loc_addr; /* 服务器端IP地址 */
	__be32			rmt_addr; /* 客户端IP地址 */
	__be16			rmt_port; /* 客户端端口号 */
	kmemcheck_bitfield_begin(flags);
	u16			snd_wscale : 4,  /* 客户端的窗口扩大因子 */
				rcv_wscale : 4,  /* 服务器端的窗口扩大因子 */
				tstamp_ok  : 1,  /* 标识本连接是否支持TIMESTAMP选项 */
				sack_ok	   : 1,  /* 标识本连接是否支持SACK选项 */
				wscale_ok  : 1,  /* 标识本连接是否支持Window Scale选项 */
				ecn_ok	   : 1,  /* 标识本连接是否支持ECN选项 */
				acked	   : 1,
				no_srccheck: 1;
	kmemcheck_bitfield_end(flags);
	struct ip_options	*opt;  /* IP选项 */
};

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

struct ip_mc_socklist;
struct ipv6_pinfo;
struct rtable;

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @daddr - Foreign IPv4 addr
 * @rcv_saddr - Bound local IPv4 addr
 * @dport - Destination port
 * @num - Local port
 * @saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @sport - Source port
 * @id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
 //它是INET域的socket表示，是对struct sock的一个扩展，
 //提供INET域的一些属性，如TTL，组播列表，IP地址，端口等
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk; 
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6_pinfo	*pinet6; //指向ipv6控制块
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	__be32			daddr;//远端地址
	__be32			rcv_saddr;//绑定的本地地址
	__be16			dport;//目的端口
	__u16			num;  //杜宇RAW_SOCKET此处为协议号
	__be32			saddr;//绑定的本地地址
	__s16			uc_ttl;
	__u16			cmsg_flags;
	struct ip_options	*opt; //存放ip选项
	__be16			sport;
	__u16			id;
	__u8			tos;
	__u8			mc_ttl;  /*多播TTL*/ 
	__u8			pmtudisc;//根据此标志的设置来设置iph->frag_off标志 
	__u8			recverr:1,
				is_icsk:1, //sock扩展是否可扩展为inet_connection_sock结构
				freebind:1,
				hdrincl:1,//
				mc_loop:1,/*多播回环设置*/ 
				transparent:1,//其含义就是可以使一个服务器程序侦听所有的IP地址，哪怕不是本机的IP地址
				mc_all:1;
	int			mc_index; /*多播设备序号*/ 
	__be32			mc_addr; /*多播地址*/ 
	struct ip_mc_socklist	*mc_list;/*多播群数组*/ 
	
	struct {
		unsigned int		flags;
		unsigned int		fragsize;//存放出口mtu值 片段大小
		struct ip_options	*opt;//存放ip选项
		struct dst_entry	*dst;
		int			length; /* Total length of all frames */
		__be32			addr;
		struct flowi		fl;
	} cork;
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->obj_size - ancestor_size);
}
#if !(defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	__inet_sk_copy_descendant(sk_to, sk_from, sizeof(struct inet_sock));
}
#endif

extern int inet_sk_rebuild_header(struct sock *sk);

extern u32 inet_ehash_secret;
extern void build_ehash_secret(void);

static inline unsigned int inet_ehashfn(struct net *net,
					const __be32 laddr, const __u16 lport,
					const __be32 faddr, const __be16 fport)
{
	return jhash_3words((__force __u32) laddr,
			    (__force __u32) faddr,
			    ((__u32) lport) << 16 | (__force __u32)fport,
			    inet_ehash_secret + net_hash_mix(net));
}

static inline int inet_sk_ehashfn(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __be32 laddr = inet->rcv_saddr;
	const __u16 lport = inet->num;
	const __be32 faddr = inet->daddr;
	const __be16 fport = inet->dport;
	struct net *net = sock_net(sk);

	return inet_ehashfn(net, laddr, lport, faddr, fport);
}

static inline struct request_sock *inet_reqsk_alloc(struct request_sock_ops *ops)
{
	struct request_sock *req = reqsk_alloc(ops);
	struct inet_request_sock *ireq = inet_rsk(req);

	if (req != NULL) {
		kmemcheck_annotate_bitfield(ireq, flags);
		ireq->opt = NULL;
	}

	return req;
}

static inline __u8 inet_sk_flowi_flags(const struct sock *sk)
{
	return inet_sk(sk)->transparent ? FLOWI_FLAG_ANYSRC : 0;
}

#endif	/* _INET_SOCK_H */
