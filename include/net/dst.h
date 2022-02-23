/*
 * net/dst.h	Protocol independent destination cache definitions.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#ifndef _NET_DST_H
#define _NET_DST_H

#include <net/dst_ops.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/rcupdate.h>
#include <linux/jiffies.h>
#include <net/neighbour.h>
#include <asm/processor.h>

/*
 * 0 - no debugging messages
 * 1 - rare events and bugs (default)
 * 2 - trace mode.
 */
#define RT_CACHE_DEBUG		0

#define DST_GC_MIN	(HZ/10)
#define DST_GC_INC	(HZ/2)
#define DST_GC_MAX	(120*HZ)

/* Each dst_entry has reference count and sits in some parent list(s).
 * When it is removed from parent list, it is "freed" (dst_free).
 * After this it enters dead state (dst->obsolete > 0) and if its refcnt
 * is zero, it can be destroyed immediately, otherwise it is added
 * to gc list and garbage collector periodically checks the refcnt.
 */

struct sk_buff;

struct dst_entry
{   
/*将路由缓存项链接在一起*/
	struct rcu_head		rcu_head;
	struct dst_entry	*child;

	/*出口设备*/
	struct net_device       *dev;
	short			error;
	/*
    若为0，表示可以正常使用
	*/
	short			obsolete;
	int			flags;
#define DST_HOST		1
#define DST_NOXFRM		2
#define DST_NOPOLICY		4
#define DST_NOHASH		8

    /*表示该表项过期的时间戳*/
	unsigned long		expires;

	unsigned short		header_len;	/* more space at head required */
	unsigned short		trailer_len;	/* space to reserve at tail */

	unsigned int		rate_tokens;

	/*对icmp redirect等类型的数据包进行限速操作*/
	unsigned long		rate_last;	/* rate limiting for ICMP */

	struct dst_entry	*path;

    /*关联的邻居项*/
	struct neighbour	*neighbour;
	struct hh_cache		*hh;
#ifdef CONFIG_XFRM
	struct xfrm_state	*xfrm;
#else
	void			*__pad1;
#endif
              /*
              对于要转发的单播数据包，input指向函数ip_forward
              对于目的地址为本机器的单播数据包,input为ip_local_deliver
              对于组播数据再有的情况下 input指向ip_mr_input   
              在有些情况下input为input_error 
              */
	int			(*input)(struct sk_buff*);  
 

	
	int			(*output)(struct sk_buff*);//output则指向函数ip_output，

    /*dst_ops指针，包括路由缓存的slab缓存块，缓存的垃圾回收函数等*/
	struct  dst_ops	        *ops;
	
    /*规格向量，主要是被tcp使用*/
	u32			metrics[RTAX_MAX];

#ifdef CONFIG_NET_CLS_ROUTE
	__u32			tclassid;
#else
	__u32			__pad2;
#endif


	/*
	 * Align __refcnt to a 64 bytes alignment
	 * (L1_CACHE_SIZE would be too much)
	 */
#ifdef CONFIG_64BIT
	long			__pad_to_align_refcnt[2];
#else
	long			__pad_to_align_refcnt[1];
#endif
	/*
	 * __refcnt wants to be on a different cache line from
	 * input/output/ops or performance tanks badly
	 */
	 /*引用计数*/
	atomic_t		__refcnt;	/* client references	*/
	/*该缓存已被使用的次数*/
	int			__use;
	/*最近一次使用该路由缓存的时间戳*/
	unsigned long		lastuse;
	union {
		struct dst_entry *next;
		struct rtable    *rt_next;
		struct rt6_info   *rt6_next;
		struct dn_route  *dn_next;
	};
};

#ifdef __KERNEL__

static inline u32
dst_metric(const struct dst_entry *dst, int metric)
{
	return dst->metrics[metric-1];
}

static inline u32 dst_mtu(const struct dst_entry *dst)
{
	u32 mtu = dst_metric(dst, RTAX_MTU);
	/*
	 * Alexey put it here, so ask him about it :)
	 */
	barrier();
	return mtu;
}

/* RTT metrics are stored in milliseconds for user ABI, but used as jiffies */
static inline unsigned long dst_metric_rtt(const struct dst_entry *dst, int metric)
{
	return msecs_to_jiffies(dst_metric(dst, metric));
}

static inline void set_dst_metric_rtt(struct dst_entry *dst, int metric,
				      unsigned long rtt)
{
	dst->metrics[metric-1] = jiffies_to_msecs(rtt);
}

static inline u32
dst_allfrag(const struct dst_entry *dst)
{
	int ret = dst_metric(dst, RTAX_FEATURES) & RTAX_FEATURE_ALLFRAG;
	/* Yes, _exactly_. This is paranoia. */
	barrier();
	return ret;
}

static inline int
dst_metric_locked(struct dst_entry *dst, int metric)
{
	return dst_metric(dst, RTAX_LOCK) & (1<<metric);
}

static inline void dst_hold(struct dst_entry * dst)
{
	/*
	 * If your kernel compilation stops here, please check
	 * __pad_to_align_refcnt declaration in struct dst_entry
	 */
	BUILD_BUG_ON(offsetof(struct dst_entry, __refcnt) & 63);
	atomic_inc(&dst->__refcnt);
}

static inline void dst_use(struct dst_entry *dst, unsigned long time)
{
	dst_hold(dst);
	dst->__use++;
	dst->lastuse = time;
}

static inline
struct dst_entry * dst_clone(struct dst_entry * dst)
{
	if (dst)
		atomic_inc(&dst->__refcnt);
	return dst;
}

extern void dst_release(struct dst_entry *dst);
static inline void skb_dst_drop(struct sk_buff *skb)
{
	if (skb->_skb_dst)
		dst_release(skb_dst(skb));
	skb->_skb_dst = 0UL;
}

/* Children define the path of the packet through the
 * Linux networking.  Thus, destinations are stackable.
 */

static inline struct dst_entry *dst_pop(struct dst_entry *dst)
{
	struct dst_entry *child = dst_clone(dst->child);

	dst_release(dst);
	return child;
}

extern int dst_discard(struct sk_buff *skb);
extern void * dst_alloc(struct dst_ops * ops);
extern void __dst_free(struct dst_entry * dst);
extern struct dst_entry *dst_destroy(struct dst_entry * dst);

static inline void dst_free(struct dst_entry * dst)
{
	if (dst->obsolete > 1)
		return;
	if (!atomic_read(&dst->__refcnt)) {
		dst = dst_destroy(dst);
		if (!dst)
			return;
	}
	__dst_free(dst);
}

static inline void dst_rcu_free(struct rcu_head *head)
{
	struct dst_entry *dst = container_of(head, struct dst_entry, rcu_head);
	dst_free(dst);
}

static inline void dst_confirm(struct dst_entry *dst)
{
	if (dst)
		neigh_confirm(dst->neighbour);
}

static inline void dst_negative_advice(struct dst_entry **dst_p)
{
	struct dst_entry * dst = *dst_p;
	if (dst && dst->ops->negative_advice)
		*dst_p = dst->ops->negative_advice(dst);
}

static inline void dst_link_failure(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	if (dst && dst->ops && dst->ops->link_failure)
		dst->ops->link_failure(skb);
}

static inline void dst_set_expires(struct dst_entry *dst, int timeout)
{
	unsigned long expires = jiffies + timeout;

	if (expires == 0)
		expires = 1;

	if (dst->expires == 0 || time_before(expires, dst->expires))
		dst->expires = expires;
}

/* Output packet to network from transport.  */
static inline int dst_output(struct sk_buff *skb)
{
	return skb_dst(skb)->output(skb); // --->ip_output()  单播
	                                  //--->ip_mc_output() 多播
}

/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
	//在路由查找函数ip_route_input_slow中 初始化input
	//如果需要对数据包转发 input设置为ip_forward
	//如果数据包目的地为本机 则input设置成ip_local_deliver
	//对于组播 有些情况会将input设置为ip_mr_input
	return skb_dst(skb)->input(skb);//实际上调用了ip_local_deliver(skb)
}

static inline struct dst_entry *dst_check(struct dst_entry *dst, u32 cookie)
{
	if (dst->obsolete)
		dst = dst->ops->check(dst, cookie);
	return dst;
}

extern void		dst_init(void);

/* Flags for xfrm_lookup flags argument. */
enum {
	XFRM_LOOKUP_WAIT = 1 << 0,
	XFRM_LOOKUP_ICMP = 1 << 1,
};

struct flowi;
#ifndef CONFIG_XFRM
static inline int xfrm_lookup(struct net *net, struct dst_entry **dst_p,
			      struct flowi *fl, struct sock *sk, int flags)
{
	return 0;
} 
static inline int __xfrm_lookup(struct net *net, struct dst_entry **dst_p,
				struct flowi *fl, struct sock *sk, int flags)
{
	return 0;
}
#else
extern int xfrm_lookup(struct net *net, struct dst_entry **dst_p,
		       struct flowi *fl, struct sock *sk, int flags);
extern int __xfrm_lookup(struct net *net, struct dst_entry **dst_p,
			 struct flowi *fl, struct sock *sk, int flags);
#endif
#endif

#endif /* _NET_DST_H */
