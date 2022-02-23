/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock 
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _REQUEST_SOCK_H
#define _REQUEST_SOCK_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/bug.h>

#include <net/sock.h>

struct request_sock;
struct sk_buff;
struct dst_entry;
struct proto;

struct request_sock_ops {
	int		family; /* 所属的协议族 */
	int		obj_size; /* 连接请求块的大小 */
	struct kmem_cache	*slab;/* 连接请求块的高速缓存 */
	char		*slab_name;
	
	//SYN+ACK段重传时调用该函数
	int		    (*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req);
    //发送ACK段时调用该函数
	void		(*send_ack)(struct sock *sk, struct sk_buff *skb,
				    struct request_sock *req);

    //发送RST段时调用该函数
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb);

	//析构函数
	void		(*destructor)(struct request_sock *req);
};

/* struct request_sock - mini sock to represent a connection request
 */
struct request_sock 
{
    //和其它struct request_sock对象形成链表
	struct request_sock		*dl_next; /* Must be first member! */
    
	//SYN段中客户端通告的MSS
	u16				mss;

	//SYN+ACK段已经重传的次数，初始化为0
	u8				retrans;
	
	u8				cookie_ts; /* syncookie: encode tcpopts in timestamp */
	/* The following two fields can be easily recomputed I think -AK */
	u32				window_clamp; /* window clamp at creation time */
	u32				rcv_wnd;	  /* rcv_wnd offered first time */
	u32				ts_recent;

	//SYN+ACK段的超时时间
	unsigned long			expires;

	//指向tcp_request_sock_ops,该函数集用于处理第三次握手的
	//ACK段以及后续accept过程中struct tcp_sock对象的创建
	const struct request_sock_ops	*rsk_ops; //proto{}->rsk_prot
	
	//连接建立前无效，建立后指向创建的tcp_sock结构
	struct sock			*sk; //tcp_sock
	u32				secid;
	u32				peer_secid;
};

static inline struct request_sock *reqsk_alloc(const struct request_sock_ops *ops)
{
	struct request_sock *req = kmem_cache_alloc(ops->slab, GFP_ATOMIC);

	if (req != NULL)
		req->rsk_ops = ops;

	return req;
}

static inline void __reqsk_free(struct request_sock *req)
{
	kmem_cache_free(req->rsk_ops->slab, req);
}

static inline void reqsk_free(struct request_sock *req)
{
	req->rsk_ops->destructor(req);
	__reqsk_free(req);
}

extern int sysctl_max_syn_backlog;

/** struct listen_sock - listen state
 *
 * @max_qlen_log - log_2 of maximal queued SYNs/REQUESTs
 */
struct listen_sock {

    //其取值为nr_table_entries以2为底的对数
	u8			max_qlen_log;
	/* 3 bytes hole, try to use */

	//当前syn_table哈希表中套接字的数目，即有多少个半连接套接字
	int			qlen;

	//服务器端会超时重传SYN+ACK段，该变量记录了那些还尚未重传过SYN+ACK段的套接字个数
	int			qlen_young;

	int			clock_hand;

    //该随机数用于访问listen_opt哈希表时计算哈希值
	u32			hash_rnd;

	//syn_table哈希表的桶大小，该值和listen()系统调用的backlog参数有关
	//看inet_listen()->inet_csk_listen_start()->reqsk_queue_alloc()
	u32			nr_table_entries;
	
	struct request_sock	*syn_table[0];//是指握手没有成功的队列
};

/** struct request_sock_queue - queue of request_socks
 *
 * @rskq_accept_head - FIFO head of established children
 * @rskq_accept_tail - FIFO tail of established children
 * @rskq_defer_accept - User waits for some data after accept()
 * @syn_wait_lock - serializer
 *
 * %syn_wait_lock is necessary only to avoid proc interface having to grab the main
 * lock sock while browsing the listening hash (otherwise it's deadlock prone).
 *
 * This lock is acquired in read mode only from listening_get_next() seq_file
 * op and it's acquired in write mode _only_ from code that is actively
 * changing rskq_accept_head. All readers that are holding the master sock lock
 * don't need to grab this lock in read mode too as rskq_accept_head. writes
 * are always protected from the main sock lock.
 */
//表示一个请求sock队列 连接已经建立
/*
tcp中分为半连接队列(处于SYN_RECVD状态)和已完成连接队列(处于established状态).这两个一个是刚接到syn,等待三次握手完成,一个是已经完成三次握手,等待accept来读取.
这里每个syn分节到来都会新建一个request_sock结构,并将它加入到listen_sock的request_sock hash表中.然后3次握手完毕后,将它放入到request_sock_queue的rskq_accept_head和rskq_accept_tail队列中.这样当accept的时候就直接从这个队列中读取了
*/

/*
inet_listen()->inet_csk_listen_start()->reqsk_queue_alloc()
*/
struct request_sock_queue {

    //head和tail用于维护已经完成三次握手，等待用户程序accept的套接字
	struct request_sock	*rskq_accept_head;
	struct request_sock	*rskq_accept_tail;

	//用于同步对listen_opt的操作
	rwlock_t		syn_wait_lock;

	//与TCP选选TCP_DEFER_ACCEPT有关
	u8			    rskq_defer_accept;
	
	/* 3 bytes hole, try to pack */
	//已经收到SYN，但是尚未完成三次握手的套接字保存在该结构中，其占用内存在listen()
	struct listen_sock	*listen_opt;
};

extern int reqsk_queue_alloc(struct request_sock_queue *queue,
			     unsigned int nr_table_entries);

extern void __reqsk_queue_destroy(struct request_sock_queue *queue);
extern void reqsk_queue_destroy(struct request_sock_queue *queue);

static inline struct request_sock *
	reqsk_queue_yank_acceptq(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	queue->rskq_accept_head = NULL;
	return req;
}

static inline int reqsk_queue_empty(struct request_sock_queue *queue)
{
	return queue->rskq_accept_head == NULL;
}

static inline void reqsk_queue_unlink(struct request_sock_queue *queue,
				      struct request_sock *req,
				      struct request_sock **prev_req)
{
	write_lock(&queue->syn_wait_lock);
	*prev_req = req->dl_next;
	write_unlock(&queue->syn_wait_lock);
}

static inline void reqsk_queue_add(struct request_sock_queue *queue,
				   struct request_sock *req,
				   struct sock *parent,
				   struct sock *child)
{
	req->sk = child;
	sk_acceptq_added(parent);

	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_head = req;
	else
		queue->rskq_accept_tail->dl_next = req;

	queue->rskq_accept_tail = req;
	req->dl_next = NULL;
}

static inline struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	WARN_ON(req == NULL);

	queue->rskq_accept_head = req->dl_next;
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_tail = NULL;

	return req;
}

static inline struct sock *reqsk_queue_get_child(struct request_sock_queue *queue,
						 struct sock *parent)
{
    //在监听套接字的完全建立连接的队列中将此队列项删除
	struct request_sock *req = reqsk_queue_remove(queue);
	
	struct sock *child = req->sk;//获得此队列项中包含的通信用的新sock结构

	WARN_ON(child == NULL);
	sk_acceptq_removed(parent);//减少完全连接队列的队列项个数
	
	__reqsk_free(req);//释放队列项
	
	return child;//返回通信用的sock结构
}

static inline int reqsk_queue_removed(struct request_sock_queue *queue,
				      struct request_sock *req)
{
	struct listen_sock *lopt = queue->listen_opt;

	if (req->retrans == 0)
		--lopt->qlen_young;

	return --lopt->qlen;
}

static inline int reqsk_queue_added(struct request_sock_queue *queue)
{
	struct listen_sock *lopt = queue->listen_opt;
	const int prev_qlen = lopt->qlen;

	lopt->qlen_young++;
	lopt->qlen++;
	return prev_qlen;
}

static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return queue->listen_opt != NULL ? queue->listen_opt->qlen : 0;
}

static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen_young;
}

static inline int reqsk_queue_is_full(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen >> queue->listen_opt->max_qlen_log;
}

static inline void reqsk_queue_hash_req(struct request_sock_queue *queue,
					u32 hash, struct request_sock *req,
					unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->expires = jiffies + timeout;
	req->retrans = 0;
	req->sk = NULL;
	req->dl_next = lopt->syn_table[hash];

	write_lock(&queue->syn_wait_lock);
	lopt->syn_table[hash] = req;
	write_unlock(&queue->syn_wait_lock);
}

#endif /* _REQUEST_SOCK_H */
