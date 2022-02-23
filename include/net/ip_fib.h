/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <net/fib_rules.h>

struct fib_config {
	u8			fc_dst_len;
	u8			fc_tos;
	u8			fc_protocol;
	u8			fc_scope;
	u8			fc_type;
	/* 3 bytes unused */
	u32			fc_table;
	__be32			fc_dst;
	__be32			fc_gw;
	int			fc_oif;
	u32			fc_flags;
	u32			fc_priority;
	__be32			fc_prefsrc;
	struct nlattr		*fc_mx;
	struct rtnexthop	*fc_mp;
	int			fc_mx_len;
	int			fc_mp_len;
	u32			fc_flow;
	u32			fc_nlflags;
	struct nl_info		fc_nlinfo;
 };

struct fib_info;

//表示下一跳
struct fib_nh {
	struct net_device	*nh_dev;//外出网络设备 网络设备被禁用时 将发送NETDEV_DOWN通知 处理fib事件的回调函数是fib_netdev_event
	struct hlist_node	nh_hash;
	struct fib_info		*nh_parent;
	unsigned		nh_flags;
	unsigned char		nh_scope;//范围
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	int			nh_weight;//每个吓一跳的权重
	int			nh_power;
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	__u32			nh_tclassid;
#endif
	int			nh_oif;//外出接口索引
	__be32			nh_gw;
};

/*
 * This structure contains data shared by many of routes.
 */
//指针指向一个fib_info实例，该实例存储着如何处理与该路由相匹配数据报的信息	
struct fib_info 
{
	struct hlist_node	fib_hash; // 链接到fib_info_hash队列 
	struct hlist_node	fib_lhash; // 链接到fib_hash_laddrhash队列  
	struct net		*fib_net;// 所属网络空间 
	int			fib_treeref; // 路由信息结构使用计数器
	atomic_t		fib_clntref;// 释放路由信息结构(fib)计数器  
	int			fib_dead;//标志路由被删除了  若此值为0 当调用free_fib_info将失败 
	unsigned		fib_flags; // 标识位
	int			fib_protocol; // 路由的路由选择协议标志符 在用户空间添加路由选择规则时 如果没有指定路由选择协议ID 此将被设置为RTPROT_BOOT
	__be32			fib_prefsrc; // 指定源IP，源地址和目的地址组成一个路由
	u32			fib_priority; // 路由优先级 
	u32			fib_metrics[RTAX_MAX];//存储各种指标(例如 初始拥塞窗口, MTU，MSS)  
#define fib_mtu fib_metrics[RTAX_MTU-1]// MTU值
#define fib_window fib_metrics[RTAX_WINDOW-1] //窗口值
#define fib_rtt fib_metrics[RTAX_RTT-1] // RTT值 
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]// MSS值(对外公开的)
                         //增加多路径选择路由的方式(用权重区别优先级) ip route add 192.168.11.1 nexthop via 192.168.11.1 weight 3 nexthop via 192.168.12.2 weight 4
	int			fib_nhs; // 吓一跳的数量 没设置多路径路由选择CONFIG_IP_ROUTE_MULTIPATH的时候其值不能超过1
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	int			fib_power; // 支持多路径时候使用
#endif
	struct fib_nh		fib_nh[0];//表示下一跳 使用多路径路由选择时 可在一条路由中指定多个吓一跳
	                              //在这种情况下将有一个下一跳数组 
#define fib_dev		fib_nh[0].nh_dev//将数据包传输到吓一跳的网络设备
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_result 
{
	unsigned char	prefixlen;//掩码长度 使用默认路由时候 其值为0
	unsigned char	nh_sel;//下一跳数量 只有一个吓一跳时候 其值为0 使用多路径路由选择时 可能存在多个下一跳
	                       //下一跳对象存储在路由选择条目(fib_info对象)的一个数组中
	unsigned char	type;//RTN_LOCAL决定了处理数据包的方式,将数据转发 本机处理 丢弃或发送一个icmp消息等
	unsigned char	scope;//范围RT_SCOPE_UNIVERSE、RT_SCOPE_LINK 
	struct fib_info *fi;//指向关联的fib_info(路由选择条目)
	
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_rule	*r;//指向关联的策略路由fib_rule
#endif
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;      
};

#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])

#define FIB_TABLE_HASHSZ 2

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])

#define FIB_TABLE_HASHSZ 256

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

//保存了在网络访问中判断一个网络地址应该走什么路由的数据表——路由规则表
//表示一个路由表
struct fib_table 
{
	struct hlist_node tb_hlist;//ipv4是&net->ipv4.fib_table_hash[INDEX]指向的哈希表
	u32		tb_id;     //标识符(例如：本地路由，主路由，默认路由) 值在1-255之间,没有配置多个表的话则只会RT_TABLE_MAIN RT_TABLE_LOCAL
	int		tb_default;//路由信息结构队列序号
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);// 查找函数
	int		(*tb_insert)(struct fib_table *, struct fib_config *);// 插入函数
	int		(*tb_delete)(struct fib_table *, struct fib_config *);// 删除路由函数
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);// 用于路由转发
	int		(*tb_flush)(struct fib_table *table);// 移除路由信息结构
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res); // 设置默认路由  

	unsigned char	tb_data[0];//fn_hash{}结构 当用LC-trie算法的时候是trie{}结构
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

#define TABLE_LOCAL_INDEX	0
#define TABLE_MAIN_INDEX	1

//以统一的方式访问路由表
static inline struct fib_table *fib_get_table(struct net *net, u32 id)
{
	struct hlist_head *ptr;

	ptr = id == RT_TABLE_LOCAL ?
		&net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX] :
		&net->ipv4.fib_table_hash[TABLE_MAIN_INDEX];
	return hlist_entry(ptr->first, struct fib_table, tb_hlist);
}

static inline struct fib_table *fib_new_table(struct net *net,//网络命名空间 
	                                                  u32 id)//表ID
{
	return fib_get_table(net, id);
}

//在路由选择表中查询路由 
static inline int fib_lookup(struct net *net, const struct flowi *flp,
			                       struct fib_result *res)
{    
	struct fib_table *table;

	//首先在本地FIB表中查询
	table = fib_get_table(net, RT_TABLE_LOCAL);
	if (!table->tb_lookup(table, flp, res))
		return 0;
	
    //在主FIB表中查询
	table = fib_get_table(net, RT_TABLE_MAIN);
	if (!table->tb_lookup(table, flp, res))
		return 0;
	return -ENETUNREACH;
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
extern int __net_init fib4_rules_init(struct net *net);
extern void __net_exit fib4_rules_exit(struct net *net);

#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif

extern int fib_lookup(struct net *n, struct flowi *flp, struct fib_result *res);

extern struct fib_table *fib_new_table(struct net *net, u32 id);
extern struct fib_table *fib_get_table(struct net *net, u32 id);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern const struct nla_policy rtm_ipv4_policy[];
extern void		ip_fib_init(void);
extern int fib_validate_source(__be32 src, __be32 dst, u8 tos, int oif,
			       struct net_device *dev, __be32 *spec_dst,
			       u32 *itag, u32 mark);
extern void fib_select_default(struct net *net, const struct flowi *flp,
			       struct fib_result *res);

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(__be32 gw, struct net_device *dev);
extern int fib_sync_down_dev(struct net_device *dev, int force);
extern int fib_sync_down_addr(struct net *net, __be32 local);
extern int fib_sync_up(struct net_device *dev);
extern __be32  __fib_res_prefsrc(struct fib_result *res);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

/* Exported by fib_{hash|trie}.c */
extern void fib_hash_init(void);
extern struct fib_table *fib_hash_table(u32 id);

static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	rtag = fib_rules_tclass(res);
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#ifdef CONFIG_PROC_FS
extern int __net_init  fib_proc_init(struct net *net);
extern void __net_exit fib_proc_exit(struct net *net);
#else
static inline int fib_proc_init(struct net *net)
{
	return 0;
}
static inline void fib_proc_exit(struct net *net)
{
}
#endif

#endif  /* _NET_FIB_H */
