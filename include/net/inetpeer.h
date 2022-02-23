/*
 *		INETPEER - A storage for permanent information about peers
 *
 *  Authors:	Andrey V. Savochkin <saw@msu.ru>
 */

#ifndef _NET_INETPEER_H
#define _NET_INETPEER_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

//存储了其正在通信的远程主机信息 和ip报头中的标识(id)用来区分不同报文
//内核为最近连接过的每个远程主机保留一个这样的结构 将其放入avl树中
struct inet_peer
{
	/* group together avl_left,avl_right,v4daddr to speedup lookups */
	//avl树中的左子树 和右子树
	struct inet_peer	*avl_left, *avl_right;
	
	__be32			v4daddr;	/* 远端peer的ip地址*/
	__u16			avl_height; //树的高度
	__u16			ip_id_count;	/* IP ID for the next packet */

	//包含所有定时器到期的peer
	struct list_head	unused;
	__u32			dtime;		/* the time of last use of not
						 * referenced entries */
	atomic_t		refcnt;
	atomic_t		rid;		/* Frag reception counter */

	//下面两个用tcp管理时间戳
	__u32			tcp_ts;
	unsigned long		tcp_ts_stamp;
};

void	inet_initpeers(void) __init;

/* can be called with or without local BH being disabled */
struct inet_peer	*inet_getpeer(__be32 daddr, int create);

/* can be called from BH context or outside */
extern void inet_putpeer(struct inet_peer *p);

extern spinlock_t inet_peer_idlock;
/* can be called with or without local BH being disabled */
static inline __u16	inet_getid(struct inet_peer *p, int more)
{
	__u16 id;

	spin_lock_bh(&inet_peer_idlock);
	id = p->ip_id_count;
	p->ip_id_count += 1 + more;
	spin_unlock_bh(&inet_peer_idlock);
	return id;
}

#endif /* _NET_INETPEER_H */
