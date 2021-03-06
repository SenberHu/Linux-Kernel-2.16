/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP router.
 *
 * Version:	@(#)route.h	1.0.4	05/27/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 * Fixes:
 *		Alan Cox	:	Reformatted. Added ip_rt_local()
 *		Alan Cox	:	Support for TCP parameters.
 *		Alexey Kuznetsov:	Major changes for new routing code.
 *		Mike McLagan    :	Routing by source
 *		Robert Olsson   :	Added rt_cache statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _ROUTE_H
#define _ROUTE_H

#include <net/dst.h>
#include <net/inetpeer.h>
#include <net/flow.h>
#include <net/inet_sock.h>
#include <linux/in_route.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <linux/ip.h>
#include <linux/cache.h>
#include <linux/security.h>

#ifndef __KERNEL__
#warning This file is not supposed to be used outside of kernel.
#endif

#define RTO_ONLINK	0x01

#define RTO_CONN	0
/* RTO_CONN is not used (being alias for 0), but preserved not to break
 * some modules referring to it. */

#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sock_flag(sk, SOCK_LOCALROUTE))

struct fib_nh;
struct inet_peer;

//最新使用过的查询路由地址的缓存地址数据表——路由缓存
//路由缓存
struct rtable
{
	union
	{
	    //dst_entry中又包含邻居项相关的信息
		struct dst_entry	dst; 
	} u;

	/* Cache lookup keys 该结构体中存放了路由缓存匹配的所有参数*/
	struct flowi		fl;//注意在cache中的查找主要是通过路由键值和下面的信息

	struct in_device	*idev; // 设备

	                          //在net->ipv4.rt_genid中 在路由表刷新的时候会更改ipv4.rt_genid中的值, 表项中的rt_genid和ipv4.rt_genid中的值不相等 则表示路由表项过期
	int			    rt_genid; // 路由id  网络命名空间（ip4）的动态路由表生成ID，可理解为版本号（或时间戳变体），是当动态路由表初始化或变更时按特定随机算法生成的
	unsigned		rt_flags;// 标识 RTCF_NOTIFY、RTCF_LOCAL、RTCF_BROADCAST、RTCF_MULTICAST、RTCF_REDIRECTED
	__u16			rt_type;// 路由类型 但播 组播或本地路由RTN_UNSPEC、RTN_UNICAST、RTN_LOCAL、RTN_BROADCAST、RTN_MULTICAST

	__be32			rt_dst;	/* Path destination	*/// 目的地址
	__be32			rt_src;	/* Path source		*/ // 源地址 
	int			    rt_iif; // 入端口

	/* Info on neighbour */
	__be32			rt_gateway;//有关邻居的信息 保留下一跳地址

	/* Miscellaneous cached information */
	__be32			rt_spec_dst; /* RFC1122 specific destination */

	///*存储ip peer相关的信息*/
	struct inet_peer	*peer; /* long-living peer info */
};

struct ip_rt_acct
{
	__u32 	o_bytes;
	__u32 	o_packets;
	__u32 	i_bytes;
	__u32 	i_packets;
};

struct rt_cache_stat 
{
        unsigned int in_hit;
        unsigned int in_slow_tot;
        unsigned int in_slow_mc;
        unsigned int in_no_route;
        unsigned int in_brd;
        unsigned int in_martian_dst;
        unsigned int in_martian_src;
        unsigned int out_hit;
        unsigned int out_slow_tot;
        unsigned int out_slow_mc;
        unsigned int gc_total;
        unsigned int gc_ignored;
        unsigned int gc_goal_miss;
        unsigned int gc_dst_overflow;
        unsigned int in_hlist_search;
        unsigned int out_hlist_search;
};

extern struct ip_rt_acct *ip_rt_acct;

struct in_device;
extern int		ip_rt_init(void);
extern void		ip_rt_redirect(__be32 old_gw, __be32 dst, __be32 new_gw,
				       __be32 src, struct net_device *dev);
extern void		rt_cache_flush(struct net *net, int how);
extern int		__ip_route_output_key(struct net *, struct rtable **, const struct flowi *flp);
extern int		ip_route_output_key(struct net *, struct rtable **, struct flowi *flp);
extern int		ip_route_output_flow(struct net *, struct rtable **rp, struct flowi *flp, struct sock *sk, int flags);
extern int		ip_route_input(struct sk_buff*, __be32 dst, __be32 src, u8 tos, struct net_device *devin);
extern unsigned short	ip_rt_frag_needed(struct net *net, struct iphdr *iph, unsigned short new_mtu, struct net_device *dev);
extern void		ip_rt_send_redirect(struct sk_buff *skb);

extern unsigned		inet_addr_type(struct net *net, __be32 addr);
extern unsigned		inet_dev_addr_type(struct net *net, const struct net_device *dev, __be32 addr);
extern void		ip_rt_multicast_event(struct in_device *);
extern int		ip_rt_ioctl(struct net *, unsigned int cmd, void __user *arg);
extern void		ip_rt_get_source(u8 *src, struct rtable *rt);
extern int		ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb);

struct in_ifaddr;
extern void fib_add_ifaddr(struct in_ifaddr *);

static inline void ip_rt_put(struct rtable * rt)
{
	if (rt)
		dst_release(&rt->u.dst);
}

//就是IPTOS_TOS_MASK(0x1E) 和3的反码做一个位与，实际上就是最低两位清0的意思
//0001 1110  & 1111 1100 = 0001 1100 = 0x1c =IPTOS_RT_MASK
#define IPTOS_RT_MASK	(IPTOS_TOS_MASK & ~3)

extern const __u8 ip_tos2prio[16];

static inline char rt_tos2priority(u8 tos)
{
	return ip_tos2prio[IPTOS_TOS(tos)>>1];
}

static inline int ip_route_connect(struct rtable **rp, //输出路由项
	                                         __be32 dst,//远端地址
                                             __be32 src, //本地地址
                                             u32 tos,  //服务
                                             int oif, //输出接口
                                             u8 protocol,//协议乐行
                                             __be16 sport, //源端口
                                             __be16 dport, //目的端口
                                             struct sock *sk,//sock
                                             int flags)//标志
{
	struct flowi fl = { .oif = oif, //输出设备接口
			    .mark = sk->sk_mark,
			    .nl_u = { .ip4_u = { .daddr = dst,//目的地址
						 .saddr = src, //源地址
						 .tos   = tos } }, //一般服务
			    .proto = protocol,//协议
			    .uli_u = { .ports =
				       { .sport = sport,  //自动选择的第一个源端口
					 .dport = dport } } }; //目的端口

	int err;
	struct net *net = sock_net(sk);

	if (inet_sk(sk)->transparent)
		fl.flags |= FLOWI_FLAG_ANYSRC;

	if (!dst || !src) {
		err = __ip_route_output_key(net, rp, &fl);
		if (err)
			return err;
		fl.fl4_dst = (*rp)->rt_dst;
		fl.fl4_src = (*rp)->rt_src;
		ip_rt_put(*rp);
		*rp = NULL;
	}
	security_sk_classify_flow(sk, &fl);
	return ip_route_output_flow(net, rp, &fl, sk, flags);
}

static inline int ip_route_newports(struct rtable **rp, u8 protocol,
				    __be16 sport, __be16 dport, struct sock *sk)
{
	if (sport != (*rp)->fl.fl_ip_sport ||
	    dport != (*rp)->fl.fl_ip_dport) {
		struct flowi fl;

		memcpy(&fl, &(*rp)->fl, sizeof(fl));
		fl.fl_ip_sport = sport;
		fl.fl_ip_dport = dport;
		fl.proto = protocol;
		ip_rt_put(*rp);
		*rp = NULL;
		security_sk_classify_flow(sk, &fl);
		return ip_route_output_flow(sock_net(sk), rp, &fl, sk, 0);
	}
	return 0;
}

extern void rt_bind_peer(struct rtable *rt, int create);

static inline struct inet_peer *rt_get_peer(struct rtable *rt)
{
	if (rt->peer)
		return rt->peer;

	rt_bind_peer(rt, 0);
	return rt->peer;
}

static inline int inet_iif(const struct sk_buff *skb)
{
	return skb_rtable(skb)->rt_iif;
}

#endif	/* _ROUTE_H */
