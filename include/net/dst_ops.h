#ifndef _NET_DST_OPS_H
#define _NET_DST_OPS_H
#include <linux/types.h>

struct dst_entry;
struct kmem_cachep;
struct net_device;
struct sk_buff;

struct dst_ops {
	unsigned short		family; //协议族 AF_INET
	__be16			protocol; //链路层协议字段 ETH_P_IP
	unsigned		gc_thresh;

	int			(*gc)(struct dst_ops *ops);//垃圾回收函数
	struct dst_entry *	(*check)(struct dst_entry *, __u32 cookie);//目前为空函数
	void			(*destroy)(struct dst_entry *);//删除路由表项的函数
	void			(*ifdown)(struct dst_entry *,
					  struct net_device *dev, int how);
	struct dst_entry *	(*negative_advice)(struct dst_entry *);//如果任何表项要重定向或者要被删除的时候就调用此函数
	void			(*link_failure)(struct sk_buff *);
	void			(*update_pmtu)(struct dst_entry *dst, u32 mtu);//更新某路由的MTU值
	int			(*local_out)(struct sk_buff *skb);//指定路由表项的大小

	atomic_t		entries;
	struct kmem_cache	*kmem_cachep;
};
#endif
