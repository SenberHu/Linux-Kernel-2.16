/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_INET protocol family socket handler.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Alan Cox, <A.Cox@swansea.ac.uk>
 *
 * Changes (see also sock.c)
 *
 *		piggy,
 *		Karl Knutson	:	Socket protocol table
 *		A.N.Kuznetsov	:	Socket death error in accept().
 *		John Richardson :	Fix non blocking error in connect()
 *					so sockets that fail to connect
 *					don't return -EINPROGRESS.
 *		Alan Cox	:	Asynchronous I/O support
 *		Alan Cox	:	Keep correct socket pointer on sock
 *					structures
 *					when accept() ed
 *		Alan Cox	:	Semantics of SO_LINGER aren't state
 *					moved to close when you look carefully.
 *					With this fixed and the accept bug fixed
 *					some RPC stuff seems happier.
 *		Niibe Yutaka	:	4.4BSD style write async I/O
 *		Alan Cox,
 *		Tony Gale 	:	Fixed reuse semantics.
 *		Alan Cox	:	bind() shouldn't abort existing but dead
 *					sockets. Stops FTP netin:.. I hope.
 *		Alan Cox	:	bind() works correctly for RAW sockets.
 *					Note that FreeBSD at least was broken
 *					in this respect so be careful with
 *					compatibility tests...
 *		Alan Cox	:	routing cache support
 *		Alan Cox	:	memzero the socket structure for
 *					compactness.
 *		Matt Day	:	nonblock connect error handler
 *		Alan Cox	:	Allow large numbers of pending sockets
 *					(eg for big web sites), but only if
 *					specifically application requested.
 *		Alan Cox	:	New buffering throughout IP. Used
 *					dumbly.
 *		Alan Cox	:	New buffering now used smartly.
 *		Alan Cox	:	BSD rather than common sense
 *					interpretation of listen.
 *		Germano Caronni	:	Assorted small races.
 *		Alan Cox	:	sendmsg/recvmsg basic support.
 *		Alan Cox	:	Only sendmsg/recvmsg now supported.
 *		Alan Cox	:	Locked down bind (see security list).
 *		Alan Cox	:	Loosened bind a little.
 *		Mike McLagan	:	ADD/DEL DLCI Ioctls
 *	Willy Konynenberg	:	Transparent proxying support.
 *		David S. Miller	:	New socket lookup architecture.
 *					Some other random speedups.
 *		Cyrus Durgin	:	Cleaned up file for kmod hacks.
 *		Andi Kleen	:	Fix inet_stream_connect TCP race.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/inet.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/arp.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/raw.h>
#include <net/icmp.h>
#include <net/ipip.h>
#include <net/inet_common.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#ifdef CONFIG_IP_MROUTE
#include <linux/mroute.h>
#endif


/* The inetsw table contains everything that inet_create needs to
 * build a new socket.
 */
static struct list_head inetsw[SOCK_MAX];
static DEFINE_SPINLOCK(inetsw_lock);

struct ipv4_config ipv4_config;
EXPORT_SYMBOL(ipv4_config);

/* New destruction routine */

void inet_sock_destruct(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_error_queue);

	sk_mem_reclaim(sk);

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != TCP_CLOSE) {
		pr_err("Attempt to release TCP socket in state %d %p\n",
		       sk->sk_state, sk);
		return;
	}
	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Attempt to release alive inet socket %p\n", sk);
		return;
	}

	WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	WARN_ON(atomic_read(&sk->sk_wmem_alloc));
	WARN_ON(sk->sk_wmem_queued);
	WARN_ON(sk->sk_forward_alloc);

	kfree(inet->opt);
	dst_release(sk->sk_dst_cache);
	sk_refcnt_debug_dec(sk);
}
EXPORT_SYMBOL(inet_sock_destruct);

/*
 *	The routines beyond this point handle the behaviour of an AF_INET
 *	socket object. Mostly it punts to the subprotocols of IP to do
 *	the work.
 */

/*
 *	Automatically bind an unbound socket.
 */

static int inet_autobind(struct sock *sk)
{
	struct inet_sock *inet;
	/* We may need to bind the socket. */
	lock_sock(sk);
	inet = inet_sk(sk);
	if (!inet->num) {
		if (sk->sk_prot->get_port(sk, 0)) {
			release_sock(sk);
			return -EAGAIN;
		}
		inet->sport = htons(inet->num);
	}
	release_sock(sk);
	return 0;
}

/*
 *	Move a socket into listening state.
 */
int inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	/*
     SS_UNCONNECTED表示已经分配了socket但连接还未建立
     不是流套接字不用listen
	*/
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;

	old_state = sk->sk_state;

	//若socket的状态不是CLOSE或LISTEN则状态错误 退出
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	 //若socket状态已经是LISTEN则只调节backlog的大小	 
	if (old_state != TCP_LISTEN) 
	{   
	    
		err = inet_csk_listen_start(sk, backlog);
		if (err)
			goto out;
	}
	//设置监听建立连接队列(以完成3次握手)的最大长度
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(inet_listen);

u32 inet_ehash_secret __read_mostly;
EXPORT_SYMBOL(inet_ehash_secret);

/*
 * inet_ehash_secret must be set exactly once
 * Instead of using a dedicated spinlock, we (ab)use inetsw_lock
 */
void build_ehash_secret(void)
{
	u32 rnd;
	do {
		get_random_bytes(&rnd, sizeof(rnd));
	} while (rnd == 0);
	spin_lock_bh(&inetsw_lock);
	if (!inet_ehash_secret)
		inet_ehash_secret = rnd;
	spin_unlock_bh(&inetsw_lock);
}
EXPORT_SYMBOL(build_ehash_secret);

static inline int inet_netns_ok(struct net *net, int protocol)
{
	int hash;
	const struct net_protocol *ipprot;

	if (net_eq(net, &init_net))
		return 1;

	hash = protocol & (MAX_INET_PROTOS - 1);
	ipprot = rcu_dereference(inet_protos[hash]);

	if (ipprot == NULL)
		/* raw IP is OK */
		return 1;
	return ipprot->netns_ok;
}

/*
 *	Create an inet socket.
 */
static int inet_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	char answer_no_check;
	int try_loading_module = 0;
	int err;

    //inet_ehash_secret用于计算hash值将建立连接的sock加入到hash表tcp_hashinfo中
    //inet_lookup_established()->__inet_lookup_established()->inet_ehashfn()
	if (unlikely(!inet_ehash_secret))
		if (sock->type != SOCK_RAW && sock->type != SOCK_DGRAM)
			build_ehash_secret();//函数创建加密数据赋值给inet_ehash_secret

	//设置socket起始的状态为SS_UNCONNECTED
	sock->state = SS_UNCONNECTED;

	/* Look for the requested type/protocol pair. */
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	
	 //inetsw的初始化是在inet_init 中将inetsw_array中的数据拷贝到inetsw中
	 //根据套接字类型找到对应的inet_protosw 
	list_for_each_entry_rcu(answer, &inetsw[sock->type], list) 
    {
        /*********************
        (1)判断传入的协议号,与socket类型需要的协议号是否一致,一致则判断传入的协议号是否为0,若不为0则找到inet_protosw结构
           若为0 则说明protocol和answer->protocol都为0,可以猜测上层使用了socket(AF_INET,SOCK_RAW,0)这样方式创建socket,这是错误的
        (2)若传入的协议号与socket类型需要的协议号不一致,若传入的协议号为0，则根据socket类型的需要来自己设置协议类型如
           socket(AF_INET,SOCK_STREAM,0),传入的协议号不为0而socket类型配对的answer->protocol为0,那么此socket类型为SOCK_RAW 
		********************************************/ 	  
		err = 0;
		/* Check the non-wild match. */
		if (protocol == answer->protocol) 
		{
			if (protocol != IPPROTO_IP)
				break; //找到了适配的inetsw[]元素 
		} 
		else 
		{   
		    /* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) 
			{
				protocol = answer->protocol;
				break;
			}
			
			if (IPPROTO_IP == answer->protocol)
				break; //到此处说明是个SOCK_RAW类型
		}
		err = -EPROTONOSUPPORT;
	}
   //到这里answer指向了合适的inetsw结构，若是TCP协议，answer指向内容如下  
    /* 
    *   .type =       SOCK_STREAM, 
    *   .protocol =   IPPROTO_TCP, 
    *   .prot =       &tcp_prot, 
    *   .ops =        &inet_stream_ops, 
    *   .no_check =   0, 
    *   .flags =      INET_PROTOSW_PERMANENT | 
    *                 INET_PROTOSW_ICSK, 
    */  
	if (unlikely(err)) {//若找inet_protosw失败,则从外部进行加载对应模块,尝试加载两次，并且每次都重新查找
	                    //若还失败,则报错
		if (try_loading_module < 2) {
			rcu_read_unlock();
			/*
			 * Be more specific, e.g. net-pf-2-proto-132-type-1
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP-type-SOCK_STREAM)
			 */
			if (++try_loading_module == 1)
				request_module("net-pf-%d-proto-%d-type-%d",
					       PF_INET, protocol, sock->type);
			/*
			 * Fall back to generic, e.g. net-pf-2-proto-132
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP)
			 */
			else
				request_module("net-pf-%d-proto-%d",
					       PF_INET, protocol);
			goto lookup_protocol;
		} else
			goto out_rcu_unlock;
	}

	err = -EPERM;
	
	//检测是否有权能创建sock
	if (answer->capability > 0 && !capable(answer->capability))
		goto out_rcu_unlock;

	err = -EAFNOSUPPORT;
	//判断协议protocol是否支持网络命名空间
	if (!inet_netns_ok(net, protocol))
		goto out_rcu_unlock;

	sock->ops = answer->ops;//inet层操作集
	answer_prot = answer->prot;//传输层操作集
	answer_no_check = answer->no_check;//发送或接收报文时候是否需要校验和
	answer_flags = answer->flags;//标志如下
	/***********************************************
    #define INET_PROTOSW_REUSE     0x01  标识端口是否能被重用 
    #define INET_PROTOSW_PERMANENT 0x02  标识此协议不能被替换或卸载
    #define INET_PROTOSW_ICSK      0x04  标识是不是连接的套接口
	****************************************/
	
	//释放读锁
	rcu_read_unlock();

	WARN_ON(answer_prot->slab == NULL);

	err = -ENOBUFS;
	//分配sock结构体内存，这里在inet_init函数初始化好的高速缓冲区中分配内存，然后做一些初始化工作
	sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot);
	if (sk == NULL)
		goto out;

	err = 0;
	sk->sk_no_check = answer_no_check;//发送或接收报文时候是否需要校验和
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = 1; //端口可以重用

	//根据sk变量得到inet_sock变量的地址
	inet = inet_sk(sk);

	//sock扩展结构体是否含有inet_connection_sock结构体
	//如tcp的sock扩展结构:tcp_sock{inet_connection_sock{inet_sock{sock}}}
	//  udp的sock扩展结构:udp_sock{{inet_sock{sock}}},此sock扩展就不包含inet_connection_sock
	inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;
	
	if (SOCK_RAW == sock->type) 
	{
		inet->num = protocol;
		if (IPPROTO_RAW == protocol)//对于RAW的IPPROTO_ICMP类型protocol为1 所以inet->hdrincl=0
			inet->hdrincl = 1;  //setsocketopt(...,IP_HDRINCL)  或者  socket(AF_INET,SOCK_RAW,IPPROTO_RAW)
	}

	//路径MTU发现是用来确定到达目的地的路径中最大传输单元(MTU)的大小
	if (ipv4_config.no_pmtu_disc)//不进行pmtu发现
		inet->pmtudisc = IP_PMTUDISC_DONT;//系统不发送IP头带有DF标志的报文
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;//策略根据路由中表项是否锁定了MTU，来决定是否设置DF位，如锁定，不设置DF位

	inet->id = 0;

    //对sk进一步初始化  并将sock和sk进行绑定
	sock_init_data(sock, sk);

	//进一步设置sk的其他属性信息
	sk->sk_destruct	   = inet_sock_destruct;
	sk->sk_protocol	   = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	inet->uc_ttl	= -1;
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_all	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;

    //增加对协议集合的引用计数
	sk_refcnt_debug_inc(sk);

    //由上面可只对于SOCK_RAW num的值不为0
	if (inet->num) 
	{
		/* It assumes that any protocol which allows
		 * the user to assign a number at socket
		 * creation time automatically
		 * shares.
		 */
		inet->sport = htons(inet->num);
		/* Add to protocol hash chains. */

		//raw_prot 对于raws 类型此处调用函数raw_hash_sk(),将sock加入到raw_v4_hashinfo哈希表中
		sk->sk_prot->hash(sk);
	}

	//若设置过传输层初始化结构
	//对于udp此处为空 对于tcp此处为tcp_v4_init_sock()
	if (sk->sk_prot->init) 
	{
	    //对于tcpv4调用tcp_v4_init_sock函数进行进一步的初始化，由于在函数sk_alloc中一些属性被设置成0了，所以在此调用进行初始化
		err = sk->sk_prot->init(sk);
		if (err)//初始化失败的话释放分配的sock
			sk_common_release(sk);
	}
out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
}

/*
Long periods when the sender is application-limited can lead to the
invalidation of the congestion window.  During periods when the TCP
sender is network-limited, the value of the congestion window is
repeatedly "revalidated" by the successful transmission of a window
of data without loss.  When the TCP sender is network-limited, there
is an incoming stream of acknowledgements that "clocks out" new data,
giving concrete evidence of recent available bandwidth in the
network.  In contrast, during periods when the TCP sender is
application-limited, the estimate of available capacity represented
by the congestion window may become steadily less accurate over time.
In particular, capacity that had once been used by the network-
limited connection might now be used by other traffic.

*/
/*
 *	The peer socket should always be NULL (or else). When we call this
 *	function we are destroying the object and from then on nobody
 *	should refer to it.
 */
int inet_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		long timeout;

		/* Applications forget to leave groups before exiting */
		ip_mc_drop_socket(sk);

		/* If linger is set, we don't return until the close
		 * is complete.  Otherwise we return immediately. The
		 * actually closing is done the same either way.
		 *
		 * If the close is due to the process exiting, we never
		 * linger..
		 */
		timeout = 0;
		if (sock_flag(sk, SOCK_LINGER) &&
		    !(current->flags & PF_EXITING))
			timeout = sk->sk_lingertime;  //通过SO_LINGER设置
		sock->sk = NULL;
		sk->sk_prot->close(sk, timeout);//TCP:tcp_close  UDP:udp_lib_close
	}
	return 0;
}
EXPORT_SYMBOL(inet_release);

/* It is off by default, see below. */
int sysctl_ip_nonlocal_bind __read_mostly;
EXPORT_SYMBOL(sysctl_ip_nonlocal_bind);

int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk = sock->sk;

	//获得sock扩展结构inet_sock
	struct inet_sock *inet = inet_sk(sk);

	unsigned short snum;
	int chk_addr_ret;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	//若协议层有自己的bind的函数 则使用它可以看raw_prot
	//我们先看tcp的实现 tcp对此量设置空,对此变量先跳过
	if (sk->sk_prot->bind) 
	{
		err = sk->sk_prot->bind(sk, uaddr, addr_len);
		goto out;
	}
	
	err = -EINVAL;
	//判断应用层传入的长度是否小于sockaddr_in结构长度
	if (addr_len < sizeof(struct sockaddr_in))
		goto out;

	//地址类型获得 数组播 单播还是回环地址
	chk_addr_ret = inet_addr_type(sock_net(sk), addr->sin_addr.s_addr);

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	 // sysctl_ip_nonlocal_bind表示是否允许绑定非本地的IP地址
	 //inet->freebind表示是否允许绑定非主机地址
	 //这里需要允许绑定非本地地址，除非是发送给自己、多播或广播
	err = -EADDRNOTAVAIL;
	if (!sysctl_ip_nonlocal_bind &&
	    !(inet->freebind || inet->transparent) &&
	    addr->sin_addr.s_addr != htonl(INADDR_ANY) &&
	    chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST &&
	    chk_addr_ret != RTN_BROADCAST)
		goto out;

    //获得绑定的端口号 
	snum = ntohs(addr->sin_port);
	
	err = -EACCES;
	//小于PROT_SOCK的端口号被系统使用 
	if (snum && snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	//设置sk->sk_lock.owned为1 表示有进程在使用此sock
	lock_sock(sk);

	/* Check these errors (active socket, double bind). */
	err = -EINVAL;
	//连接状态不是CLOSE或者已经绑定过端口号
	if (sk->sk_state != TCP_CLOSE || inet->num)
		goto out_release_sock;

	inet->rcv_saddr = inet->saddr = addr->sin_addr.s_addr;
	
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		inet->saddr = 0;  /* Use device */

    //将端口绑定到该sock若用户未指定端口,则自动进行分配
	/* Make sure we are allowed to bind here. */
	//对于tcp tcp_prot{}->inet_csk_get_port
	if (sk->sk_prot->get_port(sk, snum)) 
	{
		inet->saddr = inet->rcv_saddr = 0;
		err = -EADDRINUSE;
		goto out_release_sock;
	}

	if (inet->rcv_saddr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	
	inet->sport = htons(inet->num);//填充本地端口
	inet->daddr = 0;//远端地址和端口暂时设置为0
	inet->dport = 0;
	sk_dst_reset(sk);
	err = 0;
out_release_sock:
	release_sock(sk);
out:
	return err;
}
EXPORT_SYMBOL(inet_bind);

int inet_dgram_connect(struct socket *sock, struct sockaddr * uaddr,
		       int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (uaddr->sa_family == AF_UNSPEC)
		return sk->sk_prot->disconnect(sk, flags);

    //自动申请端口绑定到sock上
	if (!inet_sk(sk)->num && inet_autobind(sk))
		return -EAGAIN;

	//ip4_datagram_connect
	return sk->sk_prot->connect(sk, (struct sockaddr *)uaddr, addr_len);
}
EXPORT_SYMBOL(inet_dgram_connect);

static long inet_wait_for_connect(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

	/* Basic assumption: if someone sets sk->sk_err, he _must_
	 * change state of the socket from TCP_SYN_*.
	 * Connect() does not allow to get error notifications
	 * without closing the socket.
	 */
	while ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)//未决信号
			break;
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	}
	finish_wait(sk->sk_sleep, &wait);
	return timeo;
}

/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;

	lock_sock(sk);

	//协议族未知
	if (uaddr->sa_family == AF_UNSPEC) {
		//tcp调用传输层的tcp_disconnect
		err = sk->sk_prot->disconnect(sk, flags);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		goto out;
	}

	switch (sock->state) 
	{
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED://已经与远端取得连接
		err = -EISCONN;
		goto out;
	case SS_CONNECTING://正在与远端取得连接
		err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	case SS_UNCONNECTED://该socket已经被分配给一个连接  但连接尚未被建立
		err = -EISCONN;
		if (sk->sk_state != TCP_CLOSE)
			goto out;
		
		//此处调用tcp_v4_connect发送SYN包
		err = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (err < 0)
			goto out;
        
		sock->state = SS_CONNECTING;//标识连接正在处理中.....

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		 //非阻塞状况下 返回EINPROGRESS表示操作正在处理,而阻塞状态下在获得ACK包后将返回值设置为-EALREADY 
		err = -EINPROGRESS;
		break;
	}

    //如果设置了非阻塞选项 此处返回为0,否则返回sk->sk_sndtimeo 发送超时间
	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) 
	{
		/* Error code is set above */
		//若非阻塞 直接跳过睡眠，若为阻塞则schedule_timeout放弃CPU进入睡眠，等待连接的建立
		if (!timeo || !inet_wait_for_connect(sk, timeo))
			goto out;

		//根据timeo是否为长久睡眠设置返回的错误码(重新启动系统调用函数中断)
		err = sock_intr_errno(timeo);
		if (signal_pending(current))//处理未决信号
			goto out;
	}

	/* Connection was closed by RST, timeout, ICMP error
	 * or another process disconnected us.
	 */
	if (sk->sk_state == TCP_CLOSE)
		goto sock_error;

	/* sk->sk_err may be not zero now, if RECVERR was ordered by user
	 * and error was received after socket entered established state.
	 * Hence, it is handled normally after connect() return successfully.
	 */
    //设置socket状态连接建立
	sock->state = SS_CONNECTED;
	err = 0;
out:
	release_sock(sk);
	return err;

sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	if (sk->sk_prot->disconnect(sk, flags))
		sock->state = SS_DISCONNECTING;
	goto out;
}
EXPORT_SYMBOL(inet_stream_connect);

/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */
int inet_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct sock *sk1 = sock->sk;
	int err = -EINVAL;

	//调用传输层的具体连接连接过程对于TCP为tcp_prot{}->inet_csk_accept
	struct sock *sk2 = sk1->sk_prot->accept(sk1, flags, &err);

	if (!sk2)
		goto do_err;

	//lock_sock()对sk2加锁 设置sk->sk_lock.owned=1
	lock_sock(sk2);

    //若sk2的状态为一下状态，则警告
	WARN_ON(!((1 << sk2->sk_state) &
		      (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_CLOSE)));

	//将sk2和newsock进行绑定
	sock_graft(sk2, newsock);

    //设置套接字的连接状态为以连接
	newsock->state = SS_CONNECTED;
	err = 0;

	//对sk2解锁设置sk-> sk_lock.owned=0,处理sk_backlog队列上的报文
	//sk_backlog队列的作用就是，锁定时报文临时存放在此，解锁时，报文移到sk_receive_queue队列
	release_sock(sk2);
do_err:
	return err;
}
EXPORT_SYMBOL(inet_accept);


/*
 *	This does both peername and sockname.
 */
int inet_getname(struct socket *sock, struct sockaddr *uaddr,
			int *uaddr_len, int peer)
{
	struct sock *sk		= sock->sk;
	struct inet_sock *inet	= inet_sk(sk);
	struct sockaddr_in *sin	= (struct sockaddr_in *)uaddr;

	sin->sin_family = AF_INET;
	if (peer) 
	{
		if (!inet->dport ||
		    (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) &&
		     peer == 1))
			return -ENOTCONN;
		sin->sin_port = inet->dport;
		sin->sin_addr.s_addr = inet->daddr;
	} 
	else {
		__be32 addr = inet->rcv_saddr;
		if (!addr)
			addr = inet->saddr;
		sin->sin_port = inet->sport;
		sin->sin_addr.s_addr = addr;
	}
	memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
	*uaddr_len = sizeof(*sin);
	return 0;
}
EXPORT_SYMBOL(inet_getname);

int inet_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size)
{
	struct sock *sk = sock->sk;

	/* We may need to bind the socket. */
	/*
      对于raw ip: 此处的num在inet_create中对raw socket做了 inet->num = protocal(IPPROTO_ICMP(1))
	*/
	if (!inet_sk(sk)->num && inet_autobind(sk))
		return -EAGAIN;

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);//udp_sendmsg
}
EXPORT_SYMBOL(inet_sendmsg);


static ssize_t inet_sendpage(struct socket *sock, struct page *page, int offset,
			     size_t size, int flags)
{
	struct sock *sk = sock->sk;

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->num && inet_autobind(sk))
		return -EAGAIN;

	if (sk->sk_prot->sendpage)
		return sk->sk_prot->sendpage(sk, page, offset, size, flags);
	return sock_no_sendpage(sock, page, offset, size, flags);
}


int inet_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int err = 0;

	/* This should really check to make sure
	 * the socket is a TCP socket. (WHY AC...)
	 */
	how++; /* maps 0->1 has the advantage of making bit 1 rcvs and
		       1->2 bit 2 snds.
		       2->3 */
	if ((how & ~SHUTDOWN_MASK) || !how)	/* MAXINT->0 */
		return -EINVAL;

	lock_sock(sk);
	if (sock->state == SS_CONNECTING) {
		if ((1 << sk->sk_state) &
		    (TCPF_SYN_SENT | TCPF_SYN_RECV | TCPF_CLOSE))
			sock->state = SS_DISCONNECTING;
		else
			sock->state = SS_CONNECTED;
	}

	switch (sk->sk_state) 
	{
	case TCP_CLOSE:
		err = -ENOTCONN;
		/* Hack to wake up other listeners, who can poll for
		   POLLHUP, even on eg. unconnected UDP sockets -- RR */
	default:
		sk->sk_shutdown |= how;
		if (sk->sk_prot->shutdown)
			sk->sk_prot->shutdown(sk, how);
		break;

	/* Remaining two branches are temporary solution for missing
	 * close() in multithreaded environment. It is _not_ a good idea,
	 * but we have no choice until close() is repaired at VFS level.
	 */
	case TCP_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
		/* Fall through */
	case TCP_SYN_SENT:
		err = sk->sk_prot->disconnect(sk, O_NONBLOCK);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		break;
	}

	/* Wake up anyone sleeping in poll. */
	sk->sk_state_change(sk);
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(inet_shutdown);

/*
 *	ioctl() calls you can issue on an INET socket. Most of these are
 *	device configuration and stuff and very rarely used. Some ioctls
 *	pass on to the socket itself.
 *
 *	NOTE: I like the idea of a module for the config stuff. ie ifconfig
 *	loads the devconfigure module does its configuring and unloads it.
 *	There's a good 20K of config code hanging around the kernel.
 */

int inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int err = 0;
	struct net *net = sock_net(sk);

	switch (cmd) {
	case SIOCGSTAMP:
		err = sock_get_timestamp(sk, (struct timeval __user *)arg);
		break;
	case SIOCGSTAMPNS:
		err = sock_get_timestampns(sk, (struct timespec __user *)arg);
		break;
	case SIOCADDRT:
	case SIOCDELRT:
	case SIOCRTMSG:
		err = ip_rt_ioctl(net, cmd, (void __user *)arg);
		break;
	case SIOCDARP:
	case SIOCGARP:
	case SIOCSARP:
		err = arp_ioctl(net, cmd, (void __user *)arg);
		break;
	case SIOCGIFADDR:
	case SIOCSIFADDR:
	case SIOCGIFBRDADDR:
	case SIOCSIFBRDADDR:
	case SIOCGIFNETMASK:
	case SIOCSIFNETMASK:
	case SIOCGIFDSTADDR:
	case SIOCSIFDSTADDR:
	case SIOCSIFPFLAGS:
	case SIOCGIFPFLAGS:
	case SIOCSIFFLAGS:
		err = devinet_ioctl(net, cmd, (void __user *)arg);
		break;
	default:
		if (sk->sk_prot->ioctl)//tcp_ioctl udp_ioctl raw_ioctl
			err = sk->sk_prot->ioctl(sk, cmd, arg);
		else
			err = -ENOIOCTLCMD;
		break;
	}
	return err;
}
EXPORT_SYMBOL(inet_ioctl);

const struct proto_ops inet_stream_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_stream_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet_getname,
	.poll		   = tcp_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = tcp_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = tcp_sendpage,
	.splice_read	   = tcp_splice_read,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};
EXPORT_SYMBOL(inet_stream_ops);

const struct proto_ops inet_dgram_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = udp_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};
EXPORT_SYMBOL(inet_dgram_ops);

/*
 * For SOCK_RAW sockets; should be the same as inet_dgram_ops but without
 * udp_poll
 */
static const struct proto_ops inet_sockraw_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = datagram_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

static struct net_proto_family inet_family_ops = {
	.family = PF_INET,
	.create = inet_create,
	.owner	= THIS_MODULE,
};

/* Upon startup we insert all the elements in inetsw_array[] into
 * the linked list inetsw.
 */
 //初始化的时候我们会将上面数组中的的元素按套接字类型插入inetsw链表数组
static struct inet_protosw inetsw_array[] =
{
	{
		.type =       SOCK_STREAM,
		.protocol =   IPPROTO_TCP,
		.prot =       &tcp_prot,
		.ops =        &inet_stream_ops,
		.capability = -1,
		.no_check =   0,
		.flags =      INET_PROTOSW_PERMANENT |
			          INET_PROTOSW_ICSK,
	},

	{
		.type =       SOCK_DGRAM,
		.protocol =   IPPROTO_UDP,
		.prot =       &udp_prot,
		.ops =        &inet_dgram_ops,
		.capability = -1,
		.no_check =   UDP_CSUM_DEFAULT,
		.flags =      INET_PROTOSW_PERMANENT,
       },


       {
	       .type =       SOCK_RAW,
	       .protocol =   IPPROTO_IP,	/* wild card */
	       .prot =       &raw_prot,
	       .ops =        &inet_sockraw_ops,
	       .capability = CAP_NET_RAW,
	       .no_check =   UDP_CSUM_DEFAULT,
	       .flags =      INET_PROTOSW_REUSE,
       }
};

#define INETSW_ARRAY_LEN ARRAY_SIZE(inetsw_array)

void inet_register_protosw(struct inet_protosw *p)
{
	struct list_head *lh;
	struct inet_protosw *answer;
	int protocol = p->protocol;
	struct list_head *last_perm;

	spin_lock_bh(&inetsw_lock);

	if (p->type >= SOCK_MAX)
		goto out_illegal;

	/* If we are trying to override a permanent protocol, bail. */
	answer = NULL;
	last_perm = &inetsw[p->type];
	list_for_each(lh, &inetsw[p->type]) {
		answer = list_entry(lh, struct inet_protosw, list);

		/* Check only the non-wild match. */
		if (INET_PROTOSW_PERMANENT & answer->flags) {
			if (protocol == answer->protocol)
				break;
			last_perm = lh;
		}

		answer = NULL;
	}
	if (answer)
		goto out_permanent;

	/* Add the new entry after the last permanent entry if any, so that
	 * the new entry does not override a permanent entry when matched with
	 * a wild-card protocol. But it is allowed to override any existing
	 * non-permanent entry.  This means that when we remove this entry, the
	 * system automatically returns to the old behavior.
	 */
	list_add_rcu(&p->list, last_perm);
out:
	spin_unlock_bh(&inetsw_lock);

	return;

out_permanent:
	printk(KERN_ERR "Attempt to override permanent protocol %d.\n",
	       protocol);
	goto out;

out_illegal:
	printk(KERN_ERR
	       "Ignoring attempt to register invalid socket type %d.\n",
	       p->type);
	goto out;
}
EXPORT_SYMBOL(inet_register_protosw);

void inet_unregister_protosw(struct inet_protosw *p)
{
	if (INET_PROTOSW_PERMANENT & p->flags) {
		printk(KERN_ERR
		       "Attempt to unregister permanent protocol %d.\n",
		       p->protocol);
	} else {
		spin_lock_bh(&inetsw_lock);
		list_del_rcu(&p->list);
		spin_unlock_bh(&inetsw_lock);

		synchronize_net();
	}
}
EXPORT_SYMBOL(inet_unregister_protosw);

/*
 *      Shall we try to damage output packets if routing dev changes?
 */

int sysctl_ip_dynaddr __read_mostly;

static int inet_sk_reselect_saddr(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	int err;
	struct rtable *rt;
	__be32 old_saddr = inet->saddr;
	__be32 new_saddr;
	__be32 daddr = inet->daddr;

	if (inet->opt && inet->opt->srr)
		daddr = inet->opt->faddr;

	/* Query new route. */
	err = ip_route_connect(&rt, daddr, 0,
			       RT_CONN_FLAGS(sk),
			       sk->sk_bound_dev_if,
			       sk->sk_protocol,
			       inet->sport, inet->dport, sk, 0);
	if (err)
		return err;

	sk_setup_caps(sk, &rt->u.dst);

	new_saddr = rt->rt_src;

	if (new_saddr == old_saddr)
		return 0;

	if (sysctl_ip_dynaddr > 1) {
		printk(KERN_INFO "%s(): shifting inet->saddr from %pI4 to %pI4\n",
		       __func__, &old_saddr, &new_saddr);
	}

	inet->saddr = inet->rcv_saddr = new_saddr;

	/*
	 * XXX The only one ugly spot where we need to
	 * XXX really change the sockets identity after
	 * XXX it has entered the hashes. -DaveM
	 *
	 * Besides that, it does not check for connection
	 * uniqueness. Wait for troubles.
	 */
	__sk_prot_rehash(sk);
	return 0;
}

int inet_sk_rebuild_header(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = (struct rtable *)__sk_dst_check(sk, 0);
	__be32 daddr;
	int err;

	/* Route is OK, nothing to do. */
	if (rt)
		return 0;

	/* Reroute. */
	daddr = inet->daddr;
	if (inet->opt && inet->opt->srr)
		daddr = inet->opt->faddr;
{
	struct flowi fl = {
		.oif = sk->sk_bound_dev_if,
		.mark = sk->sk_mark,
		.nl_u = {
			.ip4_u = {
				.daddr	= daddr,
				.saddr	= inet->saddr,
				.tos	= RT_CONN_FLAGS(sk),
			},
		},
		.proto = sk->sk_protocol,
		.flags = inet_sk_flowi_flags(sk),
		.uli_u = {
			.ports = {
				.sport = inet->sport,
				.dport = inet->dport,
			},
		},
	};

	security_sk_classify_flow(sk, &fl);
	err = ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 0);
}
	if (!err)
		sk_setup_caps(sk, &rt->u.dst);
	else {
		/* Routing failed... */
		sk->sk_route_caps = 0;
		/*
		 * Other protocols have to map its equivalent state to TCP_SYN_SENT.
		 * DCCP maps its DCCP_REQUESTING state to TCP_SYN_SENT. -acme
		 */
		if (!sysctl_ip_dynaddr ||
		    sk->sk_state != TCP_SYN_SENT ||
		    (sk->sk_userlocks & SOCK_BINDADDR_LOCK) ||
		    (err = inet_sk_reselect_saddr(sk)) != 0)
			sk->sk_err_soft = -err;
	}

	return err;
}
EXPORT_SYMBOL(inet_sk_rebuild_header);

static int inet_gso_send_check(struct sk_buff *skb)
{
	struct iphdr *iph;
	const struct net_protocol *ops;
	int proto;
	int ihl;
	int err = -EINVAL;

	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
		goto out;

	iph = ip_hdr(skb);
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		goto out;

	if (unlikely(!pskb_may_pull(skb, ihl)))
		goto out;

	__skb_pull(skb, ihl);
	skb_reset_transport_header(skb);
	iph = ip_hdr(skb);
	proto = iph->protocol & (MAX_INET_PROTOS - 1);
	err = -EPROTONOSUPPORT;

	rcu_read_lock();
	ops = rcu_dereference(inet_protos[proto]);
	if (likely(ops && ops->gso_send_check))
		err = ops->gso_send_check(skb);
	rcu_read_unlock();

out:
	return err;
}

static struct sk_buff *inet_gso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct iphdr *iph;
	const struct net_protocol *ops;
	int proto;
	int ihl;
	int id;
	unsigned int offset = 0;

	if (!(features & NETIF_F_V4_CSUM))
		features &= ~NETIF_F_SG;

	if (unlikely(skb_shinfo(skb)->gso_type &
		     ~(SKB_GSO_TCPV4 |
		       SKB_GSO_UDP |
		       SKB_GSO_DODGY |
		       SKB_GSO_TCP_ECN |
		       0)))
		goto out;

	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
		goto out;

	iph = ip_hdr(skb);
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		goto out;

	if (unlikely(!pskb_may_pull(skb, ihl)))
		goto out;

	__skb_pull(skb, ihl);
	skb_reset_transport_header(skb);
	iph = ip_hdr(skb);
	id = ntohs(iph->id);
	proto = iph->protocol & (MAX_INET_PROTOS - 1);
	segs = ERR_PTR(-EPROTONOSUPPORT);

	rcu_read_lock();
	ops = rcu_dereference(inet_protos[proto]);
	if (likely(ops && ops->gso_segment))
		segs = ops->gso_segment(skb, features);
	rcu_read_unlock();

	if (!segs || IS_ERR(segs))
		goto out;

	skb = segs;
	do {
		iph = ip_hdr(skb);
		if (proto == IPPROTO_UDP) {
			iph->id = htons(id);
			iph->frag_off = htons(offset >> 3);
			if (skb->next != NULL)
				iph->frag_off |= htons(IP_MF);
			offset += (skb->len - skb->mac_len - iph->ihl * 4);
		} else
			iph->id = htons(id++);
		iph->tot_len = htons(skb->len - skb->mac_len);
		iph->check = 0;
		iph->check = ip_fast_csum(skb_network_header(skb), iph->ihl);
	} while ((skb = skb->next));

out:
	return segs;
}

static struct sk_buff **inet_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	const struct net_protocol *ops;
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	struct iphdr *iph;
	unsigned int hlen;
	unsigned int off;
	unsigned int id;
	int flush = 1;
	int proto;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*iph);
	iph = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		iph = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!iph))
			goto out;
	}

	proto = iph->protocol & (MAX_INET_PROTOS - 1);

	rcu_read_lock();
	ops = rcu_dereference(inet_protos[proto]);
	if (!ops || !ops->gro_receive)
		goto out_unlock;

	if (*(u8 *)iph != 0x45)
		goto out_unlock;

	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto out_unlock;

	id = ntohl(*(u32 *)&iph->id);
	flush = (u16)((ntohl(*(u32 *)iph) ^ skb_gro_len(skb)) | (id ^ IP_DF));
	id >>= 16;

	for (p = *head; p; p = p->next) {
		struct iphdr *iph2;

		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		iph2 = ip_hdr(p);

		if ((iph->protocol ^ iph2->protocol) |
		    (iph->tos ^ iph2->tos) |
		    (iph->saddr ^ iph2->saddr) |
		    (iph->daddr ^ iph2->daddr)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* All fields must match except length and checksum. */
		NAPI_GRO_CB(p)->flush |=
			(iph->ttl ^ iph2->ttl) |
			((u16)(ntohs(iph2->id) + NAPI_GRO_CB(p)->count) ^ id);

		NAPI_GRO_CB(p)->flush |= flush;
	}

	NAPI_GRO_CB(skb)->flush |= flush;
	skb_gro_pull(skb, sizeof(*iph));
	skb_set_transport_header(skb, skb_gro_offset(skb));

	pp = ops->gro_receive(head, skb);

out_unlock:
	rcu_read_unlock();

out:
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}

static int inet_gro_complete(struct sk_buff *skb)
{
	const struct net_protocol *ops;
	struct iphdr *iph = ip_hdr(skb);
	int proto = iph->protocol & (MAX_INET_PROTOS - 1);
	int err = -ENOSYS;
	__be16 newlen = htons(skb->len - skb_network_offset(skb));

	csum_replace2(&iph->check, iph->tot_len, newlen);
	iph->tot_len = newlen;

	rcu_read_lock();
	ops = rcu_dereference(inet_protos[proto]);
	if (WARN_ON(!ops || !ops->gro_complete))
		goto out_unlock;

	err = ops->gro_complete(skb);

out_unlock:
	rcu_read_unlock();

	return err;
}

int inet_ctl_sock_create(struct sock **sk, unsigned short family,
			 unsigned short type, unsigned char protocol,
			 struct net *net)
{
	struct socket *sock;
	int rc = sock_create_kern(family, type, protocol, &sock);

	if (rc == 0) {
		*sk = sock->sk;
		(*sk)->sk_allocation = GFP_ATOMIC;
		/*
		 * Unhash it so that IP input processing does not even see it,
		 * we do not wish this socket to see incoming packets.
		 */
		(*sk)->sk_prot->unhash(*sk);

		sk_change_net(*sk, net);
	}
	return rc;
}
EXPORT_SYMBOL_GPL(inet_ctl_sock_create);

unsigned long snmp_fold_field(void *mib[], int offt)
{
	unsigned long res = 0;
	int i;

	for_each_possible_cpu(i) {
		res += *(((unsigned long *) per_cpu_ptr(mib[0], i)) + offt);
		res += *(((unsigned long *) per_cpu_ptr(mib[1], i)) + offt);
	}
	return res;
}
EXPORT_SYMBOL_GPL(snmp_fold_field);

int snmp_mib_init(void *ptr[2], size_t mibsize)
{
	BUG_ON(ptr == NULL);
	ptr[0] = __alloc_percpu(mibsize, __alignof__(unsigned long long));
	if (!ptr[0])
		goto err0;
	ptr[1] = __alloc_percpu(mibsize, __alignof__(unsigned long long));
	if (!ptr[1])
		goto err1;
	return 0;
err1:
	free_percpu(ptr[0]);
	ptr[0] = NULL;
err0:
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(snmp_mib_init);

void snmp_mib_free(void *ptr[2])
{
	BUG_ON(ptr == NULL);
	free_percpu(ptr[0]);
	free_percpu(ptr[1]);
	ptr[0] = ptr[1] = NULL;
}
EXPORT_SYMBOL_GPL(snmp_mib_free);

#ifdef CONFIG_IP_MULTICAST
static const struct net_protocol igmp_protocol = {
	.handler =	igmp_rcv,
	.netns_ok =	1,
};
#endif

static const struct net_protocol tcp_protocol = {
	.handler =	tcp_v4_rcv,
	.err_handler =	tcp_v4_err,
	.gso_send_check = tcp_v4_gso_send_check,
	.gso_segment =	tcp_tso_segment,
	.gro_receive =	tcp4_gro_receive,
	.gro_complete =	tcp4_gro_complete,
	.no_policy =	1,
	.netns_ok =	1,
};

static const struct net_protocol udp_protocol = {
	.handler =	udp_rcv,
	.err_handler =	udp_err,
	.gso_send_check = udp4_ufo_send_check,
	.gso_segment = udp4_ufo_fragment,
	.no_policy =	1,
	.netns_ok =	1,
};

static const struct net_protocol icmp_protocol = {
	.handler =	icmp_rcv,
	.no_policy =	1,
	.netns_ok =	1,
};

static __net_init int ipv4_mib_init_net(struct net *net)
{
	if (snmp_mib_init((void **)net->mib.tcp_statistics,
			  sizeof(struct tcp_mib)) < 0)
		goto err_tcp_mib;
	if (snmp_mib_init((void **)net->mib.ip_statistics,
			  sizeof(struct ipstats_mib)) < 0)
		goto err_ip_mib;
	if (snmp_mib_init((void **)net->mib.net_statistics,
			  sizeof(struct linux_mib)) < 0)
		goto err_net_mib;
	if (snmp_mib_init((void **)net->mib.udp_statistics,
			  sizeof(struct udp_mib)) < 0)
		goto err_udp_mib;
	if (snmp_mib_init((void **)net->mib.udplite_statistics,
			  sizeof(struct udp_mib)) < 0)
		goto err_udplite_mib;
	if (snmp_mib_init((void **)net->mib.icmp_statistics,
			  sizeof(struct icmp_mib)) < 0)
		goto err_icmp_mib;
	if (snmp_mib_init((void **)net->mib.icmpmsg_statistics,
			  sizeof(struct icmpmsg_mib)) < 0)
		goto err_icmpmsg_mib;

	tcp_mib_init(net);
	return 0;

err_icmpmsg_mib:
	snmp_mib_free((void **)net->mib.icmp_statistics);
err_icmp_mib:
	snmp_mib_free((void **)net->mib.udplite_statistics);
err_udplite_mib:
	snmp_mib_free((void **)net->mib.udp_statistics);
err_udp_mib:
	snmp_mib_free((void **)net->mib.net_statistics);
err_net_mib:
	snmp_mib_free((void **)net->mib.ip_statistics);
err_ip_mib:
	snmp_mib_free((void **)net->mib.tcp_statistics);
err_tcp_mib:
	return -ENOMEM;
}

static __net_exit void ipv4_mib_exit_net(struct net *net)
{
	snmp_mib_free((void **)net->mib.icmpmsg_statistics);
	snmp_mib_free((void **)net->mib.icmp_statistics);
	snmp_mib_free((void **)net->mib.udplite_statistics);
	snmp_mib_free((void **)net->mib.udp_statistics);
	snmp_mib_free((void **)net->mib.net_statistics);
	snmp_mib_free((void **)net->mib.ip_statistics);
	snmp_mib_free((void **)net->mib.tcp_statistics);
}

static __net_initdata struct pernet_operations ipv4_mib_ops = {
	.init = ipv4_mib_init_net,
	.exit = ipv4_mib_exit_net,
};

static int __init init_ipv4_mibs(void)
{
	return register_pernet_subsys(&ipv4_mib_ops);
}

static int ipv4_proc_init(void);

/*
 *	IP protocol layer initialiser
 */
 int  ip_packet_type1;//自己添加 没用
static struct packet_type ip_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_IP),
	.func = ip_rcv,  //所有ipv4数据包的接收函数 包括组播和广播  主要执行完整性检查
	.gso_send_check = inet_gso_send_check,
	.gso_segment = inet_gso_segment,
	.gro_receive = inet_gro_receive,
	.gro_complete = inet_gro_complete,
};

/*sock_init  inet_init  net_dev_init  net_olddevs_init
此函数初始化一些和协议相关的函数
*/

/*
发送数据: socket通过 proto_ops{}将数据发送给sock,sock又通过proto{}将数据传送到sk_buff
收到数据: sk_buff通过net_protocol{}将数据发送给sock，sock又通过proto{}将数据传给socket，socket将数据给用户
*/
static int __init inet_init(void)
{
	struct sk_buff *dummy_skb;
	struct inet_protosw *q;
	struct list_head *r;
	int rc = -EINVAL;

	BUILD_BUG_ON(sizeof(struct inet_skb_parm) > sizeof(dummy_skb->cb));

	/*下面的三个调用先后为tcp udp raw申请proto结构 并把它挂在到proto_list上
	这三个prot是连接传输层和ip层的纽带*/
	//下面注册传输层协议操作集 
	rc = proto_register(&tcp_prot, 1);//流类型
	if (rc)
		goto out;
	rc = proto_register(&udp_prot, 1);//数据包类型
	if (rc)
		goto out_unregister_tcp_proto;
	rc = proto_register(&raw_prot, 1);//原始包
	if (rc)
		goto out_unregister_udp_proto;

    //注册INET协议族的handler  将inet地址族放到net_families数组中 其他的地址族还有 PF_NETLINK PF_UNIX PF_PACKET
    (void)sock_register(&inet_family_ops);
    

#ifdef CONFIG_SYSCTL
	ip_static_sysctl_init();
#endif

	/*下面的注册是应付从下到上即数据的接收关系 网络层根据ip协议字段来查找下面注册的结构体*/  
	if (inet_add_protocol(&icmp_protocol, IPPROTO_ICMP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add ICMP protocol\n");
	if (inet_add_protocol(&udp_protocol, IPPROTO_UDP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add UDP protocol\n");
	if (inet_add_protocol(&tcp_protocol, IPPROTO_TCP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add TCP protocol\n");
#ifdef CONFIG_IP_MULTICAST
	if (inet_add_protocol(&igmp_protocol, IPPROTO_IGMP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add IGMP protocol\n");
#endif
	///////////////////////////////////////////////////////////////////////////

	/* Register the socket-side information for inet_create. */
	for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
		INIT_LIST_HEAD(r);

	//将来会在创建socket的时候用到
	 //将inetsw_array中的元素按套接字类型注册到inetsw链表数组中
	for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
		inet_register_protosw(q);

	/*
	 *	Set the ARP module up
	 */
	//对arp进行初始化
	arp_init();

	/*
	 *	Set the IP module up
	 */

	ip_init();

	tcp_v4_init();

	/* Setup TCP slab cache for open requests. */
	tcp_init();

	/* Setup UDP memory threshold */
	udp_init();

	/* Add UDP-Lite (RFC 3828) */
	udplite4_register();

    //初始化ICMP  ->icmp_sk_init
	if (icmp_init() < 0)
		panic("Failed to create the ICMP control socket.\n");

	/*
	 *	Initialise the multicast router
	 */
#if defined(CONFIG_IP_MROUTE)
	if (ip_mr_init())
		printk(KERN_CRIT "inet_init: Cannot init ipv4 mroute\n");
#endif
	/*
	 *	Initialise per-cpu ipv4 mibs
	 */

	if (init_ipv4_mibs())
		printk(KERN_CRIT "inet_init: Cannot init ipv4 mibs\n");

	ipv4_proc_init();

    //片段初始化
	ipfrag_init();

	//设备层传输到上层需要区分是arp还是ip  在这里注册ip类型的包处理
	dev_add_pack(&ip_packet_type);

	rc = 0;
out:
	return rc;
out_unregister_udp_proto:
	proto_unregister(&udp_prot);
out_unregister_tcp_proto:
	proto_unregister(&tcp_prot);
	goto out;
}

fs_initcall(inet_init);

/* ------------------------------------------------------------------------ */

#ifdef CONFIG_PROC_FS
static int __init ipv4_proc_init(void)
{
	int rc = 0;

	if (raw_proc_init())
		goto out_raw;
	if (tcp4_proc_init())
		goto out_tcp;
	if (udp4_proc_init())
		goto out_udp;
	if (ip_misc_proc_init())
		goto out_misc;
out:
	return rc;
out_misc:
	udp4_proc_exit();
out_udp:
	tcp4_proc_exit();
out_tcp:
	raw_proc_exit();
out_raw:
	rc = -ENOMEM;
	goto out;
}

#else /* CONFIG_PROC_FS */
static int __init ipv4_proc_init(void)
{
	return 0;
}
#endif /* CONFIG_PROC_FS */

MODULE_ALIAS_NETPROTO(PF_INET);

