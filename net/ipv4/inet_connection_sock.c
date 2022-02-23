/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Support for INET connection oriented protocols.
 *
 * Authors:	See the TCP sources
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 */

#include <linux/module.h>
#include <linux/jhash.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/xfrm.h>

#ifdef INET_CSK_DEBUG
const char inet_csk_timer_bug_msg[] = "inet_csk BUG: unknown timer value\n";
EXPORT_SYMBOL(inet_csk_timer_bug_msg);
#endif

/*
 * This struct holds the first and last local port number.
 */
struct local_ports sysctl_local_ports __read_mostly = {
	.lock = SEQLOCK_UNLOCKED,
	.range = { 32768, 61000 },
};

void inet_get_local_port_range(int *low, int *high)
{
	unsigned seq;
	do {
 /*
   顺序锁是对读写锁的一种优化。
    1.读执行单元绝对不会被写执行单元阻塞。即读执行单元可以在写执行单元对被顺序锁保护的共享资源进行写操作的同时仍然可以继续读,而不必等待写执行单元完成之后再去读,同样,写执行单元也不必等待所有的读执行单元读完之后才去进行写操作
    2.写执行单元与写执行单元之间仍然是互斥的。
    3.如果读执行单元在读操作期间,写执行单元已经发生了写操作,那么,读执行单元必须重新去读数据,以便确保读到的数据是完整的。
    4.要求共享资源中不能含有指针。
    顺序锁：允许读和写操作之间的并发,也允许读与读操作之间的并发,但写与写操作之间只能是互斥的、串行的。

    若读操作期间发生了写操作，则要重读，怎样实现重读呢？
    do
    {
          seqnum = read_seqbegin(&seqlock_r);    //读开始
          ……
    }while(read_seqretry(&seqlock_r,seqnum));    //读操作期间是否发生写
 */	
		seq = read_seqbegin(&sysctl_local_ports.lock);
 
        //我们可以指定系统自动分配端口号时，端口的区间
        //proc/sys/net/ipv4/ip_local_port_range [32768	61000]
		*low = sysctl_local_ports.range[0];
		*high = sysctl_local_ports.range[1];
		
	} while (read_seqretry(&sysctl_local_ports.lock, seq));
}
EXPORT_SYMBOL(inet_get_local_port_range);

int inet_csk_bind_conflict(const struct sock *sk,
			   const struct inet_bind_bucket *tb)
{
	const __be32 sk_rcv_saddr = inet_rcv_saddr(sk);
	struct sock *sk2;
	struct hlist_node *node;
	int reuse = sk->sk_reuse;

	/*
	 * Unlike other sk lookup places we do not check
	 * for sk_net here, since _all_ the socks listed
	 * in tb->owners list belong to the same net - the
	 * one this bucket belongs to.
	 */
   //从owners链表中遍历所有的sock结构
	sk_for_each_bound(sk2, node, &tb->owners) {
		if (sk != sk2 &&
		    !inet_v6_ipv6only(sk2) &&
		    (!sk->sk_bound_dev_if ||
		     !sk2->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == sk2->sk_bound_dev_if)) 
	    {
			if (!reuse || !sk2->sk_reuse ||
			    sk2->sk_state == TCP_LISTEN) 
			{
				const __be32 sk2_rcv_saddr = inet_rcv_saddr(sk2);
				if (!sk2_rcv_saddr || !sk_rcv_saddr ||
				    sk2_rcv_saddr == sk_rcv_saddr)
					break;
			}
		}
	}
	return node != NULL;
}

EXPORT_SYMBOL_GPL(inet_csk_bind_conflict);

/* Obtain a reference to a local port for the given sock,
 * if snum is zero it means select any available local port.
 */
int inet_csk_get_port(struct sock *sk, unsigned short snum)
{  
    //Linux内核将所有socket使用的端口通过一个哈希表来管理，该哈希表存放在全局变量tcp_hashinfo中
    //sk->sk_prot->h.hashinfo对于tcp此处指向的是tcp_hashinfo
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;

	struct inet_bind_hashbucket *head;
	struct hlist_node *node;
	struct inet_bind_bucket *tb;
	int ret, attempts = 5;
	struct net *net = sock_net(sk);
	int smallest_size = -1, smallest_rover;

	local_bh_disable();

	/* 如果snum为0，系统自动为sock选择一个端口号 */ 
	if (!snum) 
	{
		int remaining, rover, low, high;

again:
	    //可以在/proc/sys/net/ipv4/ip_local_port_range文件中设置范围
		inet_get_local_port_range(&low, &high);/* 获取端口号的取值范围 */
		remaining = (high - low) + 1; /* 取值范围内端口号的个数 */

		/* 随机选取范围内的一个端口 */
		smallest_rover = rover = net_random() % remaining + low;

		smallest_size = -1;
		do 
		{
			/* 根据端口号，确定所在的哈希桶 */   
			head = &hashinfo->bhash[inet_bhashfn(net, rover,hashinfo->bhash_size)];
			
			spin_lock(&head->lock);
			
			//遍历哈希桶
			inet_bind_bucket_for_each(tb, node, &head->chain)
			{
				/* 如果端口被使用了 */
				if (ib_net(tb) == net && tb->port == rover) 
				{       
				       
						if (tb->fastreuse > 0 && sk->sk_reuse &&  //端口可重用  
							sk->sk_state != TCP_LISTEN && //状态不是LISTEN状态		
						    (tb->num_owners < smallest_size || smallest_size == -1))//寻找绑定sock最少的一个端口 
					   {
							smallest_size = tb->num_owners;/* 先记录当前端口绑定的sock是最少的*/ 
							smallest_rover = rover;/* 记下这个端口 */

							//若当前端口hash桶绑定的sock大于端口范围可以表示的端口个数
							if (atomic_read(&hashinfo->bsockets) > (high - low) + 1) 
							{
								spin_unlock(&head->lock);
								snum = smallest_rover;
								goto have_snum;//去检测冲突
							}
						}
						goto next; /* 此端口不可重用，看下一个 */  
				}
			}
			break;/* 找到了没被用的端口，退出 */ 
		next:
			spin_unlock(&head->lock);
			if (++rover > high) //先查找随机端口到high范围内
				rover = low; // 在查找low到随机端口范围内的端口
		} while (--remaining > 0);//查找端口范围内的所有端口

		/* Exhausted local port range during search?  It is not
		 * possible for us to be holding one of the bind hash
		 * locks if this test triggers, because if 'remaining'
		 * drops to zero, we broke out of the do/while loop at
		 * the top level, not from the 'break;' statement.
		 */
		ret = 1;
		if (remaining <= 0) /* 完全遍历 */ 
		{
			if (smallest_size != -1) 
			{
				snum = smallest_rover;
				goto have_snum;
			}
			goto fail;
		}
		/* OK, here is the one we will use.  HEAD is
		 * non-NULL and we hold it's mutex.
		 */
		snum = rover;
	} 
	else  //应用程序指定了具体的端口
	{
have_snum:
	    //根据端口查找hash桶
		head = &hashinfo->bhash[inet_bhashfn(net, snum,
				hashinfo->bhash_size)];
		spin_lock(&head->lock);
		inet_bind_bucket_for_each(tb, node, &head->chain)
		{
			//指定的端口被使用了
			if (ib_net(tb) == net && tb->port == snum)
				goto tb_found;
		}
	}
	tb = NULL;
	goto tb_not_found;
tb_found:
	if (!hlist_empty(&tb->owners)) 
	{
		if (tb->fastreuse > 0 && sk->sk_reuse && //端口可以被重用 
			sk->sk_state != TCP_LISTEN && //状态不是LISTEN
		    smallest_size == -1) 
		{
			goto success;//此端口可以被使用
		} 
		else //端口不可被重用
		{
			ret = 1;
			
			//绑定端口是否冲突
			//tcp_prot{}->tcp_v4_init_sock()设置icsk->icsk_af_ops = &ipv4_specific;
			if (inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb)) 
			{
				if (sk->sk_reuse && sk->sk_state != TCP_LISTEN &&
				    smallest_size != -1 &&
				    --attempts >= 0) //尝试5次绑定
				{
					spin_unlock(&head->lock);
					goto again;
				}
				goto fail_unlock;
			}
		}
	}
	
//此端口是第一次绑定	
tb_not_found:
	ret = 1;
	if (!tb && (tb = inet_bind_bucket_create(hashinfo->bind_bucket_cachep,net, head, snum)) == NULL)
		goto fail_unlock;
	
	//该端口绑定sock用的链表为空(即没有sock绑定到此端口)
	if (hlist_empty(&tb->owners)) 
	{
	    //端口可以被重用 并且状态不为LISTEN
	    //sk_reuse是sock本身是否允许端口重用
	    //fastreuse表示端口本身的属性是否可以被重用,在该端口第一次被绑定的时候设置
		if (sk->sk_reuse && sk->sk_state != TCP_LISTEN)
			tb->fastreuse = 1; //设置端口允许别重用
		else
			tb->fastreuse = 0;//端口不允许被重用
	} 
	else if (tb->fastreuse &&
		    (!sk->sk_reuse || sk->sk_state == TCP_LISTEN))
		tb->fastreuse = 0;
success:
	//是否该sock是否已经绑定过端口
	if (!inet_csk(sk)->icsk_bind_hash)
		inet_bind_hash(sk, tb, snum);
	
	WARN_ON(inet_csk(sk)->icsk_bind_hash != tb);
	ret = 0;

fail_unlock:
	spin_unlock(&head->lock);
fail:
	local_bh_enable();
	return ret;
}

EXPORT_SYMBOL_GPL(inet_csk_get_port);

/*
 * Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 */
 //等待连接的完成,连接完成在tcp_v4_do_rcv函数中
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	//初始化等待队列项,将当前进程关联到此项中
	DEFINE_WAIT(wait);
	int err;

	for (;;) {
		//将等待队列项 加入到等待队列中,并且是互斥等待,只有一个进程可以被唤醒
		//sk_sleep是一个等待队列，也就是所有阻塞在这个sock上的进程，
		//我们通知用户进程就是通过这个等待队列来做的   
		prepare_to_wait_exclusive(sk->sk_sleep, &wait,
					  TASK_INTERRUPTIBLE);  
		release_sock(sk);//释放sock锁 设置sk->sk_lock.owned为0来释放锁

		//监听套接字的全连接队列若为空 则进行等待
		if (reqsk_queue_empty(&icsk->icsk_accept_queue))
			timeo = schedule_timeout(timeo);/* 进入睡眠，直到超时或收到信号 */
		
		lock_sock(sk);//申请sock锁 设置sk->sk_lock.owned为1来占有锁
		err = 0;

		//若监听套接字全连接队列不为空则退出
		if (!reqsk_queue_empty(&icsk->icsk_accept_queue))
			break;

		err = -EINVAL;
		//若不是监听套接字,则退出,等待连接完成是在监听套接字完成的
		if (sk->sk_state != TCP_LISTEN)
			break;

		//此函数是在有信号产生的情况下,对返回值的设置 
		//若timeo为MAX_SCHEDULE_TIMEOUT则err值设置为ERESTARTSYS,重新进行系统调用,
		  //timeo为MAX_SCHEDULE_TIMEOUT说明在调用schedule_timeout的时候无时间限制,直接进行schedule
		//若timeo不为MAX_SCHEDULE_TIMEOUT则err值设置EINTR
		err = sock_intr_errno(timeo);
		//检查当前进程是否有信号处理，返回不为0表示有信号需要处理
		if (signal_pending(current))
			break;
		
		err = -EAGAIN;
		//若不是信号中断 而是时间超时 将返回EAGAIN
		if (!timeo)
			break;
	}

	//将等待队列项从等待队列摘除
	finish_wait(sk->sk_sleep, &wait);
	
	return err;
}

/*
 * This will accept the next outstanding connection.
 */
 /**********************************************
sk:监听sock
flags:这些是文件标志, 例如 O_NONBLOCK
err:传出参数 用于接收错误
******************************************************/
struct sock *inet_csk_accept(struct sock *sk, int flags, int *err)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sock *newsk;
	int error;

	//获取sock锁将sk->sk_lock.owned设置为1
	//此锁用于进程上下文和中断上下文
	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	//用于accept的sock必须处于监听状态
	error = -EINVAL;
	if (sk->sk_state != TCP_LISTEN)
		goto out_err;

	/* Find already established connection */
	//在监听套接字上的连接队列如果为空
	if (reqsk_queue_empty(&icsk->icsk_accept_queue)) {

		//设置接收超时时间,若调用accept的时候设置了O_NONBLOCK,表示马上返回不阻塞进程
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo)//如果是非阻塞模式timeo为0 则马上返回
			goto out_err;

		//将进程阻塞,等待连接的完成
		error = inet_csk_wait_for_connect(sk, timeo);
		if (error)//返回值为0说明监听套接字的完全建立连接队列不为空
			goto out_err;
	}

	//在监听套接字建立连接的队列中删除此request_sock连接项 并返回建立连接的sock
	//三次握手的完成是在tcp_v4_rcv中完成的
	newsk = reqsk_queue_get_child(&icsk->icsk_accept_queue, sk);

	//此时sock的状态应为TCP_ESTABLISHED
	WARN_ON(newsk->sk_state == TCP_SYN_RECV);
out:
	release_sock(sk);
	return newsk;
out_err:
	newsk = NULL;
	*err = error;
	goto out;
}

EXPORT_SYMBOL(inet_csk_accept);

/*
 * Using different timers for retransmit, delayed acks and probes
 * We may wish use just one timer maintaining a list of expire jiffies
 * to optimize.
 */
void inet_csk_init_xmit_timers(struct sock *sk,
			       void (*retransmit_handler)(unsigned long),
			       void (*delack_handler)(unsigned long),
			       void (*keepalive_handler)(unsigned long))
{
	struct inet_connection_sock *icsk = inet_csk(sk);

    //重传定时器 tcp_write_timer()  负责重传在指定时间内未得到确认的数据包,数据包丢失或受损会出现此情况
    //此定时器在每个数据包发送后都会启动
	setup_timer(&icsk->icsk_retransmit_timer, retransmit_handler,
			(unsigned long)sk);
	
	//延迟确认定时器 tcp_delack_timer() 推迟发送确认数据包 在tcp收到必须确认单无需马上确认的数据时得到确认
	setup_timer(&icsk->icsk_delack_timer, delack_handler,
			(unsigned long)sk);
	
    //存活定时器 tcp_keepalive_timer() 检测连接是否断开 有些情况 会话空闲时间很长 此时一方可能会断开连接  
	setup_timer(&sk->sk_timer, keepalive_handler, (unsigned long)sk);

	icsk->icsk_pending = icsk->icsk_ack.pending = 0;
}

EXPORT_SYMBOL(inet_csk_init_xmit_timers);

void inet_csk_clear_xmit_timers(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_pending = icsk->icsk_ack.pending = icsk->icsk_ack.blocked = 0;

	sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
	sk_stop_timer(sk, &icsk->icsk_delack_timer);
	sk_stop_timer(sk, &sk->sk_timer);
}

EXPORT_SYMBOL(inet_csk_clear_xmit_timers);

void inet_csk_delete_keepalive_timer(struct sock *sk)
{
	sk_stop_timer(sk, &sk->sk_timer);
}

EXPORT_SYMBOL(inet_csk_delete_keepalive_timer);

void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long len)
{
	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}

EXPORT_SYMBOL(inet_csk_reset_keepalive_timer);

struct dst_entry *inet_csk_route_req(struct sock *sk,
				     const struct request_sock *req)
{
	struct rtable *rt;
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct ip_options *opt = inet_rsk(req)->opt;
	struct flowi fl = { .oif = sk->sk_bound_dev_if,
			    .nl_u = { .ip4_u =
				      { .daddr = ((opt && opt->srr) ?
						  opt->faddr :
						  ireq->rmt_addr),
					.saddr = ireq->loc_addr,
					.tos = RT_CONN_FLAGS(sk) } },
			    .proto = sk->sk_protocol,
			    .flags = inet_sk_flowi_flags(sk),
			    .uli_u = { .ports =
				       { .sport = inet_sk(sk)->sport,
					 .dport = ireq->rmt_port } } };
	struct net *net = sock_net(sk);

	security_req_classify_flow(req, &fl);
	if (ip_route_output_flow(net, &rt, &fl, sk, 0))
		goto no_route;
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto route_err;
	return &rt->u.dst;

route_err:
	ip_rt_put(rt);
no_route:
	IP_INC_STATS_BH(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}

EXPORT_SYMBOL_GPL(inet_csk_route_req);

static inline u32 inet_synq_hash(const __be32 raddr, const __be16 rport,
				 const u32 rnd, const u32 synq_hsize)
{
	return jhash_2words((__force u32)raddr, (__force u32)rport, rnd) & (synq_hsize - 1);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#else
#define AF_INET_FAMILY(fam) 1
#endif

struct request_sock *inet_csk_search_req(const struct sock *sk,
					 struct request_sock ***prevp,
					 const __be16 rport, const __be32 raddr,
					 const __be32 laddr)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	struct request_sock *req, **prev;

	for (prev = &lopt->syn_table[inet_synq_hash(raddr, rport, lopt->hash_rnd,
						    lopt->nr_table_entries)];
	     (req = *prev) != NULL;
	     prev = &req->dl_next) {
		const struct inet_request_sock *ireq = inet_rsk(req);

		if (ireq->rmt_port == rport &&
		    ireq->rmt_addr == raddr &&
		    ireq->loc_addr == laddr &&
		    AF_INET_FAMILY(req->rsk_ops->family)) {
			WARN_ON(req->sk);
			*prevp = prev;
			break;
		}
	}

	return req;
}

EXPORT_SYMBOL_GPL(inet_csk_search_req);

//加入到半连接队列中
void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				                                     unsigned long timeout)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	//获得未完成三次握手的监听队列
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;

	const u32 h = inet_synq_hash(inet_rsk(req)->rmt_addr, inet_rsk(req)->rmt_port,
				                   lopt->hash_rnd, lopt->nr_table_entries);

	reqsk_queue_hash_req(&icsk->icsk_accept_queue, h, req, timeout);
	inet_csk_reqsk_queue_added(sk, timeout);
}

/* Only thing we need from tcp.h */
extern int sysctl_tcp_synack_retries;

EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_hash_add);

/* Decide when to expire the request and when to resend SYN-ACK */
static inline void syn_ack_recalc(struct request_sock *req, const int thresh,
				  const int max_retries,
				  const u8 rskq_defer_accept,
				  int *expire, int *resend)
{
	if (!rskq_defer_accept) {
		*expire = req->retrans >= thresh;
		*resend = 1;
		return;
	}
	*expire = req->retrans >= thresh &&
		  (!inet_rsk(req)->acked || req->retrans >= max_retries);
	/*
	 * Do not resend while waiting for data after ACK,
	 * start to resend on end of deferring period to give
	 * last chance for data or ACK to create established socket.
	 */
	*resend = !inet_rsk(req)->acked ||
		  req->retrans >= rskq_defer_accept - 1;
}

void inet_csk_reqsk_queue_prune(struct sock *parent,
				const unsigned long interval,
				const unsigned long timeout,
				const unsigned long max_rto)
{
	struct inet_connection_sock *icsk = inet_csk(parent);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct listen_sock *lopt = queue->listen_opt;
	int max_retries = icsk->icsk_syn_retries ? : sysctl_tcp_synack_retries;
	int thresh = max_retries;
	unsigned long now = jiffies;
	struct request_sock **reqp, *req;
	int i, budget;

	if (lopt == NULL || lopt->qlen == 0)
		return;

	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 3 seconds, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	if (lopt->qlen>>(lopt->max_qlen_log-1)) {
		int young = (lopt->qlen_young<<1);

		while (thresh > 2) {
			if (lopt->qlen < young)
				break;
			thresh--;
			young <<= 1;
		}
	}

	if (queue->rskq_defer_accept)
		max_retries = queue->rskq_defer_accept;

	budget = 2 * (lopt->nr_table_entries / (timeout / interval));
	i = lopt->clock_hand;

	do {
		reqp=&lopt->syn_table[i];
		while ((req = *reqp) != NULL) {
			if (time_after_eq(now, req->expires)) {
				int expire = 0, resend = 0;

				syn_ack_recalc(req, thresh, max_retries,
					       queue->rskq_defer_accept,
					       &expire, &resend);
				if (!expire &&
				    (!resend ||
				     !req->rsk_ops->rtx_syn_ack(parent, req) ||
				     inet_rsk(req)->acked)) {
					unsigned long timeo;

					if (req->retrans++ == 0)
						lopt->qlen_young--;
					timeo = min((timeout << req->retrans), max_rto);
					req->expires = now + timeo;
					reqp = &req->dl_next;
					continue;
				}

				/* Drop this request */
				inet_csk_reqsk_queue_unlink(parent, req, reqp);
				reqsk_queue_removed(queue, req);
				reqsk_free(req);
				continue;
			}
			reqp = &req->dl_next;
		}

		i = (i + 1) & (lopt->nr_table_entries - 1);

	} while (--budget > 0);

	lopt->clock_hand = i;

	if (lopt->qlen)
		inet_csk_reset_keepalive_timer(parent, interval);
}

EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_prune);

struct sock *inet_csk_clone(struct sock *sk, const struct request_sock *req,
			    const gfp_t priority)
{
	struct sock *newsk = sk_clone(sk, priority);

	if (newsk != NULL) {
		struct inet_connection_sock *newicsk = inet_csk(newsk);

		newsk->sk_state = TCP_SYN_RECV;
		newicsk->icsk_bind_hash = NULL;

		inet_sk(newsk)->dport = inet_rsk(req)->rmt_port;
		inet_sk(newsk)->num = ntohs(inet_rsk(req)->loc_port);
		inet_sk(newsk)->sport = inet_rsk(req)->loc_port;
		newsk->sk_write_space = sk_stream_write_space;

		newicsk->icsk_retransmits = 0;
		newicsk->icsk_backoff	  = 0;
		newicsk->icsk_probes_out  = 0;

		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&newicsk->icsk_accept_queue, 0, sizeof(newicsk->icsk_accept_queue));
		security_inet_csk_clone(newsk, req);
	}
	return newsk;
}

EXPORT_SYMBOL_GPL(inet_csk_clone);

/*
 * At this point, there should be no process reference to this
 * socket, and thus no user references at all.  Therefore we
 * can assume the socket waitqueue is inactive and nobody will
 * try to jump onto it.
 */
void inet_csk_destroy_sock(struct sock *sk)
{
	WARN_ON(sk->sk_state != TCP_CLOSE);
	WARN_ON(!sock_flag(sk, SOCK_DEAD));

	/* It cannot be in hash table! */
	WARN_ON(!sk_unhashed(sk));

	/* If it has not 0 inet_sk(sk)->num, it must be bound */
	WARN_ON(inet_sk(sk)->num && !inet_csk(sk)->icsk_bind_hash);

	sk->sk_prot->destroy(sk);

	sk_stream_kill_queues(sk);

	xfrm_sk_free_policy(sk);

	sk_refcnt_debug_release(sk);

	percpu_counter_dec(sk->sk_prot->orphan_count);
	sock_put(sk);
}

EXPORT_SYMBOL(inet_csk_destroy_sock);

int inet_csk_listen_start(struct sock *sk, const int nr_table_entries)
{
    //创建sock的大小为sizeof(tcp_sock) 对sock结构进行了扩展
    //可以看到tcp_sock中第一个元素是inet_connection_sock,
    //inet_connection_sock中第一个元素是inet_sock
    //inet_sock中第一个元素是sock结构，所以可以在此处进行强制转换获得这几种结构,
    //这几种结构的首地址是一样的
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	//初始化icsk_accept_queue其中包含两个队列 一个是存放已经建立连接的sock(3次握手已经完成)
	//一个是存放半连接的sock(收到syn包,还未完成3次握手)
	int rc = reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries);

	if (rc != 0)
		return rc;

    //此处先置为0 在条用此函数的函数中会重新设置此值
	sk->sk_max_ack_backlog = 0;
	sk->sk_ack_backlog = 0;
	
	//清零inet_connection_sock中的icsk_ack(延时ack控制数据结构)
	inet_csk_delack_init(sk);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	 //设置sock状态为LISTEN
	sk->sk_state = TCP_LISTEN;

	//获得端口 inet_csk_get_port,端口存在或端口分配成功都返回0
	if (!sk->sk_prot->get_port(sk, inet->num)) {
		inet->sport = htons(inet->num);

		//重置缓存路由项 
		sk_dst_reset(sk);
		
		//tcp inet_hash
		sk->sk_prot->hash(sk);//将sock放入监听hash表中

		return 0;
	}

	sk->sk_state = TCP_CLOSE;

	//销毁监听套接字的连接队列
	__reqsk_queue_destroy(&icsk->icsk_accept_queue);
	return -EADDRINUSE;
}

EXPORT_SYMBOL_GPL(inet_csk_listen_start);

/*
 *	This routine closes sockets which have been at least partially
 *	opened, but not yet accepted.
 */
void inet_csk_listen_stop(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock *acc_req;
	struct request_sock *req;

	inet_csk_delete_keepalive_timer(sk);

	/* make all the listen_opt local to us */
	acc_req = reqsk_queue_yank_acceptq(&icsk->icsk_accept_queue);

	/* Following specs, it would be better either to send FIN
	 * (and enter FIN-WAIT-1, it is normal close)
	 * or to send active reset (abort).
	 * Certainly, it is pretty dangerous while synflood, but it is
	 * bad justification for our negligence 8)
	 * To be honest, we are not able to make either
	 * of the variants now.			--ANK
	 */
	reqsk_queue_destroy(&icsk->icsk_accept_queue);

	while ((req = acc_req) != NULL) {
		struct sock *child = req->sk;

		acc_req = req->dl_next;

		local_bh_disable();
		bh_lock_sock(child);
		WARN_ON(sock_owned_by_user(child));
		sock_hold(child);

		sk->sk_prot->disconnect(child, O_NONBLOCK);

		sock_orphan(child);

		percpu_counter_inc(sk->sk_prot->orphan_count);

		inet_csk_destroy_sock(child);

		bh_unlock_sock(child);
		local_bh_enable();
		sock_put(child);

		sk_acceptq_removed(sk);
		__reqsk_free(req);
	}
	WARN_ON(sk->sk_ack_backlog);
}

EXPORT_SYMBOL_GPL(inet_csk_listen_stop);

void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	const struct inet_sock *inet = inet_sk(sk);

	sin->sin_family		= AF_INET;
	sin->sin_addr.s_addr	= inet->daddr;
	sin->sin_port		= inet->dport;
}

EXPORT_SYMBOL_GPL(inet_csk_addr2sockaddr);

#ifdef CONFIG_COMPAT
int inet_csk_compat_getsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_getsockopt != NULL)
		return icsk->icsk_af_ops->compat_getsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->getsockopt(sk, level, optname,
					     optval, optlen);
}

EXPORT_SYMBOL_GPL(inet_csk_compat_getsockopt);

int inet_csk_compat_setsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, unsigned int optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_setsockopt != NULL)
		return icsk->icsk_af_ops->compat_setsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->setsockopt(sk, level, optname,
					     optval, optlen);
}

EXPORT_SYMBOL_GPL(inet_csk_compat_setsockopt);
#endif
