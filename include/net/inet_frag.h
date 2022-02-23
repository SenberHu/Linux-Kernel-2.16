#ifndef __NET_FRAG_H__
#define __NET_FRAG_H__

struct netns_frags {
	int			nqueues;
	atomic_t		mem;
	struct list_head	lru_list;

	/* sysctls */
	int			timeout;
	int			high_thresh;
	int			low_thresh;
};

struct inet_frag_queue {
	struct hlist_node	list;
	struct netns_frags	*net;
	struct list_head	lru_list;   /* lru list member */
	spinlock_t		lock;
	atomic_t		refcnt;
	struct timer_list	timer;      /*组装超时定时器*/
	struct sk_buff		*fragments; /*接收到的IP碎片链表 将分段放入队列中fragments */
	ktime_t			stamp;   // 最新一个碎片的时间戳
	int			len;        /* 数据包的总长度*/
	int			meat;// meat是所有碎片实际长度的累加
	__u8			last_in;/* 标志最后一个分片或第一个分片是否到达 INET_FRAG_FIRST_IN*/

#define INET_FRAG_COMPLETE	4 // 数据已经完整
#define INET_FRAG_FIRST_IN	2 // 第一个包到达
#define INET_FRAG_LAST_IN	1 // 最后一个包到达
};

#define INETFRAGS_HASHSZ		64

struct inet_frags {
	struct hlist_head	hash[INETFRAGS_HASHSZ];
	rwlock_t		lock;
	u32			rnd;
	int			qsize;
	int			secret_interval;
	struct timer_list	secret_timer;

	unsigned int		(*hashfn)(struct inet_frag_queue *);
	void			(*constructor)(struct inet_frag_queue *q,
						void *arg);
	void			(*destructor)(struct inet_frag_queue *);
	void			(*skb_free)(struct sk_buff *);
	int			(*match)(struct inet_frag_queue *q,
						void *arg);
	void			(*frag_expire)(unsigned long data);
};

void inet_frags_init(struct inet_frags *);
void inet_frags_fini(struct inet_frags *);

void inet_frags_init_net(struct netns_frags *nf);
void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f);

void inet_frag_kill(struct inet_frag_queue *q, struct inet_frags *f);
void inet_frag_destroy(struct inet_frag_queue *q,
				struct inet_frags *f, int *work);
int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f);
struct inet_frag_queue *inet_frag_find(struct netns_frags *nf,
		struct inet_frags *f, void *key, unsigned int hash)
	__releases(&f->lock);

static inline void inet_frag_put(struct inet_frag_queue *q, struct inet_frags *f)
{
	if (atomic_dec_and_test(&q->refcnt))
		inet_frag_destroy(q, f, NULL);
}

#endif
