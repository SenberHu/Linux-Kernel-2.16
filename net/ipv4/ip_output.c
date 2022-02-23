/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) output module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 *	See ip_input.c for original log
 *
 *	Fixes:
 *		Alan Cox	:	Missing nonblock feature in ip_build_xmit.
 *		Mike Kilburn	:	htons() missing in ip_build_xmit.
 *		Bradford Johnson:	Fix faulty handling of some frames when
 *					no route is found.
 *		Alexander Demenshin:	Missing sk/skb free in ip_queue_xmit
 *					(in case if packet not accepted by
 *					output firewall rules)
 *		Mike McLagan	:	Routing by source
 *		Alexey Kuznetsov:	use new route cache
 *		Andi Kleen:		Fix broken PMTU recovery and remove
 *					some redundant tests.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Andi Kleen	: 	Replace ip_reply with ip_send_reply.
 *		Andi Kleen	:	Split fast and slow ip_build_xmit path
 *					for decreased register pressure on x86
 *					and more readibility.
 *		Marc Boucher	:	When call_out_firewall returns FW_QUEUE,
 *					silently drop skb instead of failing with -EPERM.
 *		Detlev Wengorz	:	Copy protocol for fragments.
 *		Hirokazu Takahashi:	HW checksumming for outgoing UDP
 *					datagrams.
 *		Hirokazu Takahashi:	sendfile() on UDP works now.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

int sysctl_ip_default_ttl __read_mostly = IPDEFTTL;

/* Generate a checksum for an outgoing IP datagram. */
//计算外出封包的ip校验和
__inline__ void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

int __ip_local_out(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);
	//对报头计算校验和
	ip_send_check(iph);
	return nf_hook(PF_INET, NF_INET_LOCAL_OUT, skb, NULL, skb_dst(skb)->dev,
		       dst_output);
}

int ip_local_out(struct sk_buff *skb)
{
	int err;

	err = __ip_local_out(skb);
	if (likely(err == 1))
		err = dst_output(skb);

	return err;
}
EXPORT_SYMBOL_GPL(ip_local_out);

/* dev_loopback_xmit for use with netfilter. */
static int ip_dev_loopback_xmit(struct sk_buff *newskb)
{
	skb_reset_mac_header(newskb);
	__skb_pull(newskb, skb_network_offset(newskb));
	newskb->pkt_type = PACKET_LOOPBACK;
	newskb->ip_summed = CHECKSUM_UNNECESSARY;
	WARN_ON(!skb_dst(newskb));
	netif_rx(newskb);
	return 0;
}

static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

	if (ttl < 0)
		ttl = dst_metric(dst, RTAX_HOPLIMIT);
	return ttl;
}

/*
 *		Add an ip header to a skbuff and send it out.
 *
 */
 ///由tcp协议来发送SYN ACK消息
int ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
			  __be32 saddr, __be32 daddr, struct ip_options *opt)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = skb_rtable(skb);
	struct iphdr *iph;

	/* Build the IP header. */
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = inet->tos;
	if (ip_dont_fragment(sk, &rt->u.dst))
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->daddr    = rt->rt_dst;
	iph->saddr    = rt->rt_src;
	iph->protocol = sk->sk_protocol;
	ip_select_ident(iph, &rt->u.dst, sk);

	if (opt && opt->optlen) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, daddr, rt, 0);
	}

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	/* Send it out. */
	return ip_local_out(skb);
}

EXPORT_SYMBOL_GPL(ip_build_and_send_pkt);

static inline int ip_finish_output2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev; //出口设备
	unsigned int hh_len = LL_RESERVED_SPACE(dev);

	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTBCAST, skb->len);

	/* Be paranoid, rather than too clever. */
	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL) 
		{
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

	if (dst->hh)
		return neigh_hh_output(dst->hh, skb); //dev_queue_xmit() 发送数据到驱动
	else if (dst->neighbour)
		
		//转到邻居子系统处理 
		return dst->neighbour->output(skb);//neigh_resolve_output

	if (net_ratelimit())
		printk(KERN_DEBUG "ip_finish_output2: No header cache and no neighbour!\n");
	kfree_skb(skb);
	return -EINVAL;
}

static inline int ip_skb_dst_mtu(struct sk_buff *skb)
{
	struct inet_sock *inet = skb->sk ? inet_sk(skb->sk) : NULL;

	return (inet && inet->pmtudisc == IP_PMTUDISC_PROBE) ?
	       skb_dst(skb)->dev->mtu : dst_mtu(skb_dst(skb));
}


//进行连接邻居子系统
static int ip_finish_output(struct sk_buff *skb)
{
#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
	if (skb_dst(skb)->xfrm != NULL) 
	{
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(skb);
	}
#endif
	if (skb->len > ip_skb_dst_mtu(skb) && !skb_is_gso(skb))
		return ip_fragment(skb, ip_finish_output2);//对数据进行分段
	else
		return ip_finish_output2(skb);//将数据发出
}

int ip_mc_output(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct rtable *rt = skb_rtable(skb);
	struct net_device *dev = rt->u.dst.dev;

	/*
	 *	If the indicated interface is up and running, send the packet.
	 */
	IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 *	Multicasts are looped back for other local users
	 */

	if (rt->rt_flags&RTCF_MULTICAST) {
		if ((!sk || inet_sk(sk)->mc_loop)
#ifdef CONFIG_IP_MROUTE
		/* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    && ((rt->rt_flags&RTCF_LOCAL) || !(IPCB(skb)->flags&IPSKB_FORWARDED))
#endif
		) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb)
				NF_HOOK(PF_INET, NF_INET_POST_ROUTING, newskb,
					NULL, newskb->dev,
					ip_dev_loopback_xmit);
		}

		/* Multicasts with ttl 0 must not go beyond the host */
		if (ip_hdr(skb)->ttl == 0) {
			kfree_skb(skb);
			return 0;
		}
	}

	if (rt->rt_flags&RTCF_BROADCAST) {
		struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
		if (newskb)
			NF_HOOK(PF_INET, NF_INET_POST_ROUTING, newskb, NULL,
				newskb->dev, ip_dev_loopback_xmit);
	}

	return NF_HOOK_COND(PF_INET, NF_INET_POST_ROUTING, skb, NULL, skb->dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

//dst_output->ip_output
int ip_output(struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK_COND(PF_INET, NF_INET_POST_ROUTING, skb, NULL, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

/*
ipfragok:主要由sctp使用 用来指出是否允许分段
*/
int ip_queue_xmit(struct sk_buff *skb, int ipfragok)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_options *opt = inet->opt;
	struct rtable *rt;
	struct iphdr *iph;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
    //缓冲区是否已经设置正确路由信息
	rt = skb_rtable(skb);
	if (rt != NULL)
		goto packet_routed;

	/* Make sure we can route this packet. */
	//套接字已经缓存了一个路径
	rt = (struct rtable *)__sk_dst_check(sk, 0);

    //在路由查找子系统中获得的结果为空
	if (rt == NULL) 
	{
		__be32 daddr;

		/* Use correct destination address if we have options. */
		//将目的地址暂时设置成最终目的地址
		daddr = inet->daddr;
		
		if(opt && opt->srr)   //设置了源路由  将目的地设置成原路径的下一个跳点
			daddr = opt->faddr;

		{
			struct flowi fl = { .oif = sk->sk_bound_dev_if,
					            .mark = sk->sk_mark,
					            .nl_u = { .ip4_u ={ .daddr = daddr,
							                        .saddr = inet->saddr,
							                        .tos = RT_CONN_FLAGS(sk) 
							                      } 
			                             },	
					            .proto = sk->sk_protocol,
					            .flags = inet_sk_flowi_flags(sk),
					            .uli_u = { .ports ={ .sport = inet->sport,
							                         .dport = inet->dport 
							                       }
										 } 
								};

			/* If this fails, retransmit mechanism of transport layer will
			 * keep trying until route appears or the connection times
			 * itself out.
			 */
			//LSM安全机制 
			security_sk_classify_flow(sk, &fl);

			//在路由选在子系统中进行查找
			if (ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 0))
				goto no_route;
		}

		//将出口设备所具有的一些功能存储在套接字sk中
		sk_setup_caps(sk, &rt->u.dst);
	}
	
	//将skb->_skb_dst设置路由表项,dst_clone增加了路由表项的使用计数
    //将路径存储在skb中
	skb_dst_set(skb, dst_clone(&rt->u.dst));

packet_routed:
	//包含严格原路径选项 并且该选项提供的下一个跳点和路由表传回的下个跳点不吻合
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto no_route;
	
    /*接下来处理ip报头 准备发送数据*/

	//数据包来自L4 skb->data指向传输层,skb_push将skb->data向后移动 添加ip头
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	//设置L3报头 
	skb_reset_network_header(skb);

	//获得ip头  
	iph = ip_hdr(skb);

	//设置 版本 ip头固定长 和TOS
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));

	//ip是否分段
	if (ip_dont_fragment(sk, &rt->u.dst) && !ipfragok)
		iph->frag_off = htons(IP_DF);//标志3位  片偏移13位, IP_DF为0x4000即 010 0000000000000， 010 DF位为1 表示不分片
	else
		iph->frag_off = 0;
	
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->protocol = sk->sk_protocol;//设置协议字段
	iph->saddr    = rt->rt_src; //设置源地址
	iph->daddr    = rt->rt_dst;//设置目的地址
	/* Transport layer set skb->h.foo itself. */

	//若存在ip头选项 增加ip报头长度
	if (opt && opt->optlen) 
	{
		iph->ihl += opt->optlen >> 2;//将ip头固定长 + 选项的长度

		//根据选项的内容在ipv4报头内创建选项
		//最后一个参数 0表示不会进行分段
		ip_options_build(skb, opt, inet->daddr, rt, 0);
	}

	//根据是否可能分段而在报头中设定ip ID
	ip_select_ident_more(iph, &rt->u.dst, sk,
			     (skb_shinfo(skb)->gso_segs ?: 1) - 1);

	skb->priority = sk->sk_priority;//根据不同优先级将报文放入不同队列 
	skb->mark = sk->sk_mark;

    //发送数据包
	return ip_local_out(skb);

no_route:
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}


static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	skb_dst_drop(to);
	skb_dst_set(to, dst_clone(skb_dst(from)));
	to->dev = from->dev;
	to->mark = from->mark;

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
	nf_copy(to, from);
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
	to->nf_trace = from->nf_trace;
#endif
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	to->ipvs_property = from->ipvs_property;
#endif
	skb_copy_secmark(to, from);
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 */
/*
将长于出站网卡MTU的数据包 进行分段
ip_finish_output->ip_fragment
*/
int ip_fragment(struct sk_buff *skb, //包含要被分段的ip封包的缓冲区 此封包含有一个已经初始化的ip报头
                       int (*output)(struct sk_buff *)//传输方法 将数据包进行发送的方法ip_finish_output2
                       )
{
	struct iphdr *iph;
	int raw = 0;
	int ptr;//要被分段的封包里的偏移量  它的值随分段工作进行移动
	struct net_device *dev;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs, pad;
	int offset;
	__be16 not_last_frag;//当前片段后还有其他片段 则此值设为真
	struct rtable *rt = skb_rtable(skb);
	int err = 0;

	dev = rt->u.dst.dev;

	/*
	 *	Point into the IP datagram header.
	 */
	iph = ip_hdr(skb);

	//ip设置了标志DF不进行分段(意思为需要分段的ip包 却被设置了DF不分段标志
	if (unlikely((iph->frag_off & htons(IP_DF)) && !skb->local_df)) 
	{

		//更新统计信息IPSTATS_MIB_FRAGFAILS
		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
		//发送ICMP错误消息 
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			       htonl(ip_skb_dst_mtu(skb)));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	/*
	 *	Setup starting values.
	 */
    //计算头部长度
	hlen = iph->ihl * 4;

	//计算除去头部后mtu的大小 即首先计算最大的IP包中IP净荷的长度 =MTU-IP包头长度
	mtu = dst_mtu(&rt->u.dst) - hlen;	  /* Size of data space */
	IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 */
	/* 
    * 如果L4对已经将数据分片则会将分片结果放入 skb_shinfo(skb)->frag_list
    * 因此这里首先先判断frag_list链表是否为空,不为空则进行快速路径发送 为空则进行慢速路径发送
    */  
	if (skb_has_frags(skb)) 
	{
		struct sk_buff *frag;

		//计算数据的总长度
		int first_len = skb_pagelen(skb);
		int truesizes = 0;

		 //数据总长度-ip头后 > 大于mtu净值
		if (first_len - hlen > mtu ||
		    ((first_len - hlen) & 7) ||
		    (iph->frag_off & htons(IP_MF|IP_OFFSET)) ||
		    skb_cloned(skb))
			goto slow_path;

	    skb_walk_frags(skb, frag) 
		{
			/* Correct geometry. */
			if (frag->len > mtu ||
			    ((frag->len & 7) && frag->next) ||
			    skb_headroom(frag) < hlen)
			    goto slow_path;//转向慢速路径

			/* Partially cloned skb? */
			//判断是否为共享
			/*
             分片不能被共享，这是因为在fast path 中，需要加给每个分片不同的ip头(而并 
             不会复制每个分片)。因此在fast path中是不可接受的。而在 
             slow path中，就算有共享也无所谓，因为他会复制每一个分片， 
             使用一个新的buff。    
			*/
			if (skb_shared(frag))
				goto slow_path;

			BUG_ON(frag->sk);
			if (skb->sk) 
			{
				frag->sk = skb->sk;
				frag->destructor = sock_wfree;
			}
			truesizes += frag->truesize;
	    }

		/* Everything is OK. Generate! */

		err = 0;
		offset = 0;
		frag = skb_shinfo(skb)->frag_list;

		//将skb_shinfo(skb)->frag_list设置为NULL
		skb_frag_list_init(skb);

		//保存非线性数据长度
		skb->data_len = first_len - skb_headlen(skb);

		skb->truesize -= truesizes;
		skb->len = first_len;
		iph->tot_len = htons(first_len);
		iph->frag_off = htons(IP_MF);//设置MF标志 表示此分段不是最后一个分段

		//计算ip首部校验和
		ip_send_check(iph);

		//偏离frag_list 创建分段
		for (;;) 
		{
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) 
			{
				frag->ip_summed = CHECKSUM_NONE;
			    //ip_fragment是传输层调用  skb->data指向的是传输层
				skb_reset_transport_header(frag);//设置传输层指针
				__skb_push(frag, hlen);//在skb中加入ip头长
				skb_reset_network_header(frag);//设置网络层指针

				//拷贝ip头
				memcpy(skb_network_header(frag), iph, hlen);

				//获得ip头
				iph = ip_hdr(frag);

				//ip总长度
				iph->tot_len = htons(frag->len);
				ip_copy_metadata(frag, skb);

				//仅对第一个分段
				if (offset == 0)
					ip_options_fragment(frag);
				
				offset += skb->len - hlen;//计算偏移值			
				iph->frag_off = htons(offset>>3);//frags_off偏移量的单位为8字节
				
				if (frag->next != NULL)//若不是最后一个分片 则设置MF标志,此标志标志是否为最后一个分段
					iph->frag_off |= htons(IP_MF);
				
				/* Ready, complete checksum */
				//计算校验和
				ip_send_check(iph);
			}

			//发送上一个分段
			err = output(skb);
               
			if (!err)//发送成功IPSTATS_MIB_FRAGCREATES 增加统计计数
				IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGCREATES);
			
			//发生错误 或最后一个分段 则退出循环
			if (err || !frag)
				break;
            
			skb = frag;
			frag = skb->next;
			skb->next = NULL;
		}

		if (err == 0) 
		{ 
		    //增加统计计数  IPSTATS_MIB_FRAGOKS ip包发送成功数
			IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGOKS);
			return 0;
		}

		//发生了错误
		while (frag) 
		{
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
		return err;
	}

//采用慢速路径发送
slow_path:

	//帧有效载荷的长度 
	//left初值为ip封包的长度
	left = skb->len - hlen;		/* Space per frame */

	//指向分片的数据
	ptr = raw + hlen;		/* Where to start from */

	/* for bridged IP traffic encapsulated inside f.e. a vlan header,
	 * we need to make room for the encapsulating header
	 */
	/* 处理桥接、VLAN、PPPOE相关MTU */
	pad = nf_bridge_pad(skb);

	//链路层保留空间 进行16字节对齐
	ll_rs = LL_RESERVED_SPACE_EXTRA(rt->u.dst.dev, pad);
	mtu -= pad;

	/*
	 *	Fragment the datagram.
	 */
    //得到ip 中的偏移值
	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;

	//是否为最后一个分段
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */
	 /* 开始为循环处理，每一个分片创建一个skb buffer */ 
	while (left > 0) {
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		//长度是否大于MTU
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending upto and including the packet end
		   then align the next start on an eight byte boundary */

		//不是最后一个分段  进行8字节对齐
		if (len < left)	
		{
			len &= ~7;
		}
		/*
		 *	Allocate buffer.
		 */
        //分配缓冲区长度=(ip有效载荷的长度+ip报头的长度 + l2头的长度)
		if ((skb2 = alloc_skb(len+hlen+ll_rs, GFP_ATOMIC)) == NULL) {
			NETDEBUG(KERN_INFO "IP: frag: no memory for new fragment!\n");
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */
         /* 调用ip_copy_metadata复制一些相同的值的域 */
		ip_copy_metadata(skb2, skb);

		 /* 保留L2 header空间 */ 
		skb_reserve(skb2, ll_rs);
		skb_put(skb2, len + hlen);
		skb_reset_network_header(skb2);
		skb2->transport_header = skb2->network_header + hlen;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */
       /* 将每一个分片的ip包都关联到源包的socket */  
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);

		/*
		 *	Copy the packet header into the new buffer.
		 */
        //将数据包报头复制到新缓冲区
		skb_copy_from_linear_data(skb, skb_network_header(skb2), hlen);

		/*
		 *	Copy a block of the IP datagram.
		 */
		//复制ip数据块
		if (skb_copy_bits(skb, ptr, skb_transport_header(skb2), len))
			BUG();
		/* 分片的数据剩余长度 */ 
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		 /* 填充相应的ip头 */ 
		iph = ip_hdr(skb2);
		iph->frag_off = htons((offset >> 3));

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		  /* 第一个包，因此进行ip_option处理 */ 
		if (offset == 0)
			ip_options_fragment(skb);

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		//不是最后一个分片 设置MF标志
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);

		//更新数据指针和偏移量
		ptr += len;
		offset += len;

		/*
		 *	Put this fragment into the sending queue.
		 */
		/* 更新包头的数据长度 */  
		iph->tot_len = htons(len + hlen);
        /* 重新计算校验 */   
		ip_send_check(iph);

		//将数据进行传输
		err = output(skb2);
		if (err)
			goto fail;

		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGCREATES);
	}
	kfree_skb(skb);
	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb);
	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
	return err;
}

EXPORT_SYMBOL(ip_fragment);

int
ip_generic_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{
	struct iovec *iov = from;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (memcpy_fromiovecend(to, iov, offset, len) < 0)
			return -EFAULT;
	} else {
		__wsum csum = 0;
		if (csum_partial_copy_fromiovecend(to, iov, offset, len, &csum) < 0)
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}
	return 0;
}

static inline __wsum
csum_page(struct page *page, int offset, int copy)
{
	char *kaddr;
	__wsum csum;
	kaddr = kmap(page);
	csum = csum_partial(kaddr + offset, copy, 0);
	kunmap(page);
	return csum;
}

static inline int ip_ufo_append_data(struct sock *sk,
			int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
			void *from, int length, int hh_len, int fragheaderlen,
			int transhdrlen, int mtu, unsigned int flags)
{
	struct sk_buff *skb;
	int err;

	/* There is support for UDP fragmentation offload by network
	 * device, so create one single skb packet containing complete
	 * udp datagram
	 */
	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL) {
		skb = sock_alloc_send_skb(sk,
			hh_len + fragheaderlen + transhdrlen + 20,
			(flags & MSG_DONTWAIT), &err);

		if (skb == NULL)
			return err;

		/* reserve space for Hardware header */
		skb_reserve(skb, hh_len);

		/* create space for UDP/IP header */
		skb_put(skb, fragheaderlen + transhdrlen);

		/* initialize network header pointer */
		skb_reset_network_header(skb);

		/* initialize protocol header pointer */
		skb->transport_header = skb->network_header + fragheaderlen;

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum = 0;
		sk->sk_sndmsg_off = 0;

		/* specify the length of each IP datagram fragment */
		skb_shinfo(skb)->gso_size = mtu - fragheaderlen;
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
		__skb_queue_tail(&sk->sk_write_queue, skb);
	}

	return skb_append_datato_frags(sk, skb, getfrag, from,
				       (length - transhdrlen));
}

/*
 *	ip_append_data() and ip_append_page() can make one large IP datagram
 *	from many pieces of data. Each pieces will be holded on the socket
 *	until ip_push_pending_frames() is called. Each piece can be a page
 *	or non-page data.
 *
 *	Not only UDP, other transport protocols - e.g. raw sockets - can use
 *	this interface potentially.
 *
 *	LATER: length must be adjusted by pad at tail, when it is required.
 */

//此函数是那些L4层想数据暂时缓存所使用的函数
 //此函数不仅暂时缓存数据 也以透明方式产生一些最佳大小的片段  使得ip层稍后更容易处理分段
 //共不处理分段的传输协议UDP使用  此函数不发送数据包 只准备数据
 //要想将缓存的数据刷新发送是由ip_push_pending_frames来完成的
 
int ip_append_data(struct sock *sk,//要发送数据的sock

                            //将实际数据从用户拷贝到skb的回调函数 根据L4协议的不同 还有些不同的情况需要处理,比如TCP需要计算
                            //校验和，为了使所有的L4使用ip_append_data在这里加入getfrag来处理不同的情况
                            
                            int getfrag(void *from, 
		                                char *to, 
		                                int offset, 
		                                int len,
		                                int odd, 
		                                struct sk_buff *skb),  //此函数用于处理from指针,将数据拷贝到即将建立的数据片段中 

                            void *from, //L4及以上数据 包括L4头部 可能是来自用户空间的
                            int length, //from指向的数据的长度
                            int transhdrlen,//传输(L4)报头的尺寸
		                    struct ipcm_cookie *ipc,//发送ip包需要的信息  包括首部字段的值 选项等 
		                    struct rtable **rtp,//目标路由项  此函数依赖调用者来获得路由信息
		                    unsigned int flags)//MSG_MORE MSG_PROBE
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;

	struct ip_options *opt = NULL;//要加入ip头的ip选项
	int hh_len;
	int exthdrlen;//外部报头(IPsec套件中协议使用的报头长度)
	int mtu; //和路由相关的PMTU值
	int copy;
	int err;
	int offset = 0;
	unsigned int maxfraglen, 
		         fragheaderlen;
	int csummode = CHECKSUM_NONE;
	struct rtable *rt;

	/*MSG_PROBE标记表示探测，意味着调用者对部分信息信息(MTU)感兴趣,没必要实际发送数据*/
	if (flags & MSG_PROBE)
		return 0;

	//发送队列为空为第一个分段 保存一些基本信息 
	if (skb_queue_empty(&sk->sk_write_queue)) 
	{
		/*
		 * setup for corking.
		 */
		opt = ipc->opt;
		if (opt) 
		{		    
			if (inet->cork.opt == NULL) 
			{ 
			    //创建一个抑制(cork)ip选项 看UDP_CORK
				inet->cork.opt = kmalloc(sizeof(struct ip_options) + 40, sk->sk_allocation);
				if (unlikely(inet->cork.opt == NULL))
					return -ENOBUFS;
			}
			//复制ipc(ipcm_cookie)的ip选项复制到其中
			memcpy(inet->cork.opt, opt, sizeof(struct ip_options)+opt->optlen);
			inet->cork.flags |= IPCORK_OPT;
			inet->cork.addr = ipc->addr;
		}
		rt = *rtp;//路由
		if (unlikely(!rt))
			return -EFAULT;
		/*
		 * We steal reference to this route, caller should not release it
		 */
		*rtp = NULL;
		
		//从路由项中获取mtu存入fragsize中(根据是否设置PMTU路径发现设置mtu值)
		inet->cork.fragsize = mtu = inet->pmtudisc == IP_PMTUDISC_PROBE ?
					                                      rt->u.dst.dev->mtu :
					                                      dst_mtu(rt->u.dst.path);
		inet->cork.dst = &rt->u.dst; //保存路由表项
		inet->cork.length = 0;
		sk->sk_sndmsg_page = NULL;
		sk->sk_sndmsg_off = 0;

		//只有第一个片段存在外部报头
		if ((exthdrlen = rt->u.dst.header_len) != 0) 
		{
			length += exthdrlen;
			transhdrlen += exthdrlen;
		}
	}
	
	else //不是第一个ip数据分片 则从cork中获取第一个ip数据分片时候保存的信息
	{
	
		rt = (struct rtable *)inet->cork.dst;
		if (inet->cork.flags & IPCORK_OPT)
			opt = inet->cork.opt;

		//L4首部和 IPsec首部只存在于第一个分片中  后续的分片设置为0
		transhdrlen = 0; //由于每个ip封包都需要l4报头 所以根据此值可以用来区分是第一个片段还是不是第一个片段 
		exthdrlen = 0;
		
		mtu = inet->cork.fragsize;
	}

	//根据目标路由项的发送设备计算给L2首部预留的最大空间
	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);

	//ip首部加上选项的总长度
	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	
	//一个ip片段的最大长度 将数据可用长度缩减至8字节对齐
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	//一个ip封包的最大长度为64k,如果cork.length(累计的所有ip分片的总长度)+length(当前分片长度)超出64k-ip头长
	//则出错
	if (inet->cork.length  +  length > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu-exthdrlen);
		return -EMSGSIZE;
	}

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
	// transhdrlen > 0说明这是第一个分片,我们不希望他在将来被分片
	//length + fragheaderlen <= mtu说明不需要分片  可以整发出去
	
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->u.dst.dev->features & NETIF_F_V4_CSUM &&
	    !exthdrlen)
		csummode = CHECKSUM_PARTIAL;

    //记录ip片段的长度 
	inet->cork.length += length;
	
	//(需要发送的数据长度大于MTU或者队列不为空)
	//协议为UDP
	//设置特性为NETIF_F_UFO
	if (((length> mtu) || !skb_queue_empty(&sk->sk_write_queue)) &&
	    (sk->sk_protocol == IPPROTO_UDP) &&
	    (rt->u.dst.dev->features & NETIF_F_UFO)) 
	{
		err = ip_ufo_append_data(sk, getfrag, from, length, hh_len,
					 fragheaderlen, transhdrlen, mtu,
					 flags);
		if (err)
			goto error;
		return 0;

	}

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */

	//队列是否为空
	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		goto alloc_new_skb;//为空队列  也就是将分配第一个片段

	while (length > 0) //是否还有数据
	{
		//初始化ip片段中剩余的空间量
		copy = mtu - skb->len;

	    //copy小于length说明此时的skb不会是最后一个skb需要将 长度缩减至8字节对齐
	    //最后一个skb数据长度可以不用8字节对齐
		if (copy < length)
			copy = maxfraglen - skb->len;//将copy缩减至8字节对齐的长度

		//若copy大于0 则说明skb还有一些可用空间
		//若等于0 则说明此skb空间不足 需要分配新的skb
        //若小于0则说明之前skb的数据溢出 需要将溢出的数据放入下一个skb中
		if (copy <= 0) 
		{
			char *data;
			unsigned int datalen;
			unsigned int fraglen;
			unsigned int fraggap;
			unsigned int alloclen;
			struct sk_buff *skb_prev;
alloc_new_skb:
			skb_prev = skb;
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen; //数据溢出的量
			else
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			datalen = length + fraggap;
			if (datalen > mtu - fragheaderlen)//数据大小超出mtu值
				datalen = maxfraglen - fragheaderlen;//剩余的空间量
			fraglen = datalen + fragheaderlen; //数据量和ip头加起来的总大小

            //MSG_MORE 指出是否将有更多数据将要发送
            //NETIF_F_SG 指出设备是否支持分散/聚集 IO
            //决定分配空间的大小
			if ((flags & MSG_MORE) && !(rt->u.dst.dev->features&NETIF_F_SG))
				alloclen = mtu;//使用最大尺寸分配空间
			else //使用了分散聚集IO 或者 没有设置MSG_MORE标志  都将使用确切尺寸分配空间 
				alloclen = datalen + fragheaderlen;

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 */
			if (datalen == length + fraggap) //说明此片段能放下所有的数据 这将是最后一个片段
				alloclen += rt->u.dst.trailer_len; //加上保留空间的大小

			//第一个ip片段
			if (transhdrlen) 
			{
				skb = sock_alloc_send_skb(sk,
						 alloclen + hh_len + 15,
						(flags & MSG_DONTWAIT), &err);
			} 
			else 
			{
				skb = NULL;
				//发送缓冲区是否已经塞满
				if (atomic_read(&sk->sk_wmem_alloc) <=
				    2 * sk->sk_sndbuf)
					skb = sock_wmalloc(sk,
							   alloclen + hh_len + 15, 1,
							   sk->sk_allocation);
				if (unlikely(skb == NULL))
					err = -ENOBUFS;
				else
					/* only the initial fragment is
					   time stamped */
					ipc->shtx.flags = 0;
			}
			if (skb == NULL)
				goto error;

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = csummode;//只有第一个分段会将此值设置为CHECKSUM_PARTIAL
			                          //后续将会被设置为CHECKSUM_NONE
			skb->csum = 0;
			skb_reserve(skb, hh_len);
			*skb_tx(skb) = ipc->shtx;

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fraglen);
			skb_set_network_header(skb, exthdrlen);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			data += fragheaderlen;

			if (fraggap) 
			{
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			copy = datalen - transhdrlen - fraggap;
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}
	
			offset += copy;
			length -= datalen - fraggap;//计算还剩余的数据量
			transhdrlen = 0;
			exthdrlen = 0;
			csummode = CHECKSUM_NONE;

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		if (copy > length)
			copy = length;

        //不支持分散/聚集IO
		if (!(rt->u.dst.dev->features&NETIF_F_SG)) 
		{
			unsigned int off;
			off = skb->len;
			if (getfrag(from, skb_put(skb, copy),
					offset, copy, off, skb) < 0) 
			{
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} 
		else 
	    {
			int i = skb_shinfo(skb)->nr_frags;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i-1];
			struct page *page = sk->sk_sndmsg_page;
			int off = sk->sk_sndmsg_off;
			unsigned int left;

			if (page && (left = PAGE_SIZE - off) > 0) 
			{
				if (copy >= left)
					copy = left;
				if (page != frag->page) 
				{
					if (i == MAX_SKB_FRAGS) 
					{
						err = -EMSGSIZE;
						goto error;
					}
					get_page(page);
					skb_fill_page_desc(skb, i, page, sk->sk_sndmsg_off, 0);
					frag = &skb_shinfo(skb)->frags[i];
				}
			} 
			else if (i < MAX_SKB_FRAGS) 
			{
				if (copy > PAGE_SIZE)
					copy = PAGE_SIZE;
				page = alloc_pages(sk->sk_allocation, 0);
				if (page == NULL)  
				{
					err = -ENOMEM;
					goto error;
				}
				sk->sk_sndmsg_page = page;
				sk->sk_sndmsg_off = 0;

				skb_fill_page_desc(skb, i, page, 0, 0);
				frag = &skb_shinfo(skb)->frags[i];
			} 
			else 
			{
				err = -EMSGSIZE;
				goto error;
			}
			if (getfrag(from, page_address(frag->page)+frag->page_offset+frag->size, offset, copy, skb->len, skb) < 0) {
				err = -EFAULT;
				goto error;
			}
			sk->sk_sndmsg_off += copy;
			frag->size += copy;
			skb->len += copy;
			skb->data_len += copy;
			skb->truesize += copy;
			atomic_add(copy, &sk->sk_wmem_alloc);
		}
		offset += copy;
		length -= copy;
	}

	return 0;

error:
	inet->cork.length -= length;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}

ssize_t	ip_append_page(struct sock *sk, struct page *page,
		       int offset, size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct rtable *rt;
	struct ip_options *opt = NULL;
	int hh_len;
	int mtu;
	int len;
	int err;
	unsigned int maxfraglen, fragheaderlen, fraggap;

	if (inet->hdrincl)
		return -EPERM;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue))
		return -EINVAL;

	rt = (struct rtable *)inet->cork.dst;
	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	if (!(rt->u.dst.dev->features&NETIF_F_SG))
		return -EOPNOTSUPP;

	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);
	mtu = inet->cork.fragsize;

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	if (inet->cork.length + size > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu);
		return -EMSGSIZE;
	}

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		return -EINVAL;

	inet->cork.length += size;
	if ((sk->sk_protocol == IPPROTO_UDP) &&
	    (rt->u.dst.dev->features & NETIF_F_UFO)) {
		skb_shinfo(skb)->gso_size = mtu - fragheaderlen;
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
	}


	while (size > 0) {
		int i;

		if (skb_is_gso(skb))
			len = size;
		else {

			/* Check if the remaining data fits into current packet. */
			len = mtu - skb->len;
			if (len < size)
				len = maxfraglen - skb->len;
		}
		if (len <= 0) {
			struct sk_buff *skb_prev;
			int alloclen;

			skb_prev = skb;
			fraggap = skb_prev->len - maxfraglen;

			alloclen = fragheaderlen + hh_len + fraggap + 15;
			skb = sock_wmalloc(sk, alloclen, 1, sk->sk_allocation);
			if (unlikely(!skb)) {
				err = -ENOBUFS;
				goto error;
			}

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			skb_put(skb, fragheaderlen + fraggap);
			skb_reset_network_header(skb);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(skb_prev,
								   maxfraglen,
						    skb_transport_header(skb),
								   fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		i = skb_shinfo(skb)->nr_frags;
		if (len > size)
			len = size;
		if (skb_can_coalesce(skb, i, page, offset)) {
			skb_shinfo(skb)->frags[i-1].size += len;
		} else if (i < MAX_SKB_FRAGS) {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, len);
		} else {
			err = -EMSGSIZE;
			goto error;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			__wsum csum;
			csum = csum_page(page, offset, len);
			skb->csum = csum_block_add(skb->csum, csum, skb->len);
		}

		skb->len += len;
		skb->data_len += len;
		skb->truesize += len;
		atomic_add(len, &sk->sk_wmem_alloc);
		offset += len;
		size -= len;
	}
	return 0;

error:
	inet->cork.length -= size;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}

static void ip_cork_release(struct inet_sock *inet)
{
	inet->cork.flags &= ~IPCORK_OPT;
	kfree(inet->cork.opt);
	inet->cork.opt = NULL;
	dst_release(inet->cork.dst);
	inet->cork.dst = NULL;
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 */
int ip_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = (struct rtable *)inet->cork.dst;
	struct iphdr *iph;
	__be16 df = 0;
	__u8 ttl;
	int err = 0;

	//取得第一个缓冲区,后续的缓冲区在后面都会排入第一个缓冲区的frag_list链表中
	if ((skb = __skb_dequeue(&sk->sk_write_queue)) == NULL)
		goto out;
	tail_skb = &(skb_shinfo(skb)->frag_list);
    
	/* move skb->data to ip header from ext header */
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));

    //将后续的缓冲区排入第一个缓冲区的frag_list中 
	while ((tmp_skb = __skb_dequeue(&sk->sk_write_queue)) != NULL) 
	{
		__skb_pull(tmp_skb, skb_network_header_len(skb));
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	if (inet->pmtudisc < IP_PMTUDISC_DO)
		skb->local_df = 1;

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If local_df is set too, we still allow to fragment this frame
	 * locally. */
	if (inet->pmtudisc >= IP_PMTUDISC_DO ||
	    (skb->len <= dst_mtu(&rt->u.dst) &&
	     ip_dont_fragment(sk, &rt->u.dst)))
		 df = htons(IP_DF);

	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	//ttl的设定要根基是否为多播而定
	if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->u.dst);

	//对ip报头进行填写 可以看出在有多个ip段时候  只对第一个ip片段填写报头
	iph = (struct iphdr *)skb->data;
	iph->version = 4;
	iph->ihl = 5;
	if (opt)  //有ip选项 调用ip_options_build()处理ip选项
	{
		iph->ihl += opt->optlen>>2; //更新ip头的长度
		//传递最后一个参数为0 说明它正在填写第一个片段的选项
		ip_options_build(skb, opt, inet->cork.addr, rt, 0);
	}
	
	iph->tos = inet->tos;
	iph->frag_off = df;
	ip_select_ident(iph, &rt->u.dst, sk);
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	iph->saddr = rt->rt_src;
	iph->daddr = rt->rt_dst;

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;
	/*
	 * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
	 * on dst refcount
	 */
	inet->cork.dst = NULL;
	skb_dst_set(skb, &rt->u.dst);

	if (iph->protocol == IPPROTO_ICMP)
		icmp_out_count(net, ((struct icmphdr *)
			skb_transport_header(skb))->type);

	/* Netfilter gets whole the not fragmented skb. */
	err = ip_local_out(skb);
	if (err) {
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			goto error;
	}

out:
	ip_cork_release(inet);
	return err;

error:
	IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	goto out;
}

/*
 *	Throw away all pending data on the socket.
 */
void ip_flush_pending_frames(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue_tail(&sk->sk_write_queue)) != NULL)
		kfree_skb(skb);

	ip_cork_release(inet_sk(sk));
}


/*
 *	Fetch data from kernel space and fill in checksum if needed.
 */
static int ip_reply_glue_bits(void *dptr, char *to, int offset,
			      int len, int odd, struct sk_buff *skb)
{
	__wsum csum;

	csum = csum_partial_copy_nocheck(dptr+offset, to, len, 0);
	skb->csum = csum_block_add(skb->csum, csum, odd);
	return 0;
}

/*
 *	Generic function to send a packet as reply to another packet.
 *	Used to send TCP resets so far. ICMP should use this function too.
 *
 *	Should run single threaded per socket because it uses the sock
 *     	structure to pass arguments.
 */
 //由tcp使用 来发送ACK和Rest消息 
void ip_send_reply(struct sock *sk, struct sk_buff *skb, struct ip_reply_arg *arg,
		   unsigned int len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct {
		struct ip_options	opt;
		char			data[40];
	} replyopts;
	struct ipcm_cookie ipc;
	__be32 daddr;
	struct rtable *rt = skb_rtable(skb);

	if (ip_options_echo(&replyopts.opt, skb))
		return;

	daddr = ipc.addr = rt->rt_src;
	ipc.opt = NULL;
	ipc.shtx.flags = 0;

	if (replyopts.opt.optlen) {
		ipc.opt = &replyopts.opt;

		if (ipc.opt->srr)
			daddr = replyopts.opt.faddr;
	}

	{
		struct flowi fl = { .oif = arg->bound_dev_if,
				    .nl_u = { .ip4_u =
					      { .daddr = daddr,
						.saddr = rt->rt_spec_dst,
						.tos = RT_TOS(ip_hdr(skb)->tos) } },
				    /* Not quite clean, but right. */
				    .uli_u = { .ports =
					       { .sport = tcp_hdr(skb)->dest,
						 .dport = tcp_hdr(skb)->source } },
				    .proto = sk->sk_protocol,
				    .flags = ip_reply_arg_flowi_flags(arg) };
		security_skb_classify_flow(skb, &fl);
		if (ip_route_output_key(sock_net(sk), &rt, &fl))
			return;
	}

	/* And let IP do all the hard work.

	   This chunk is not reenterable, hence spinlock.
	   Note that it uses the fact, that this function is called
	   with locally disabled BH and that sk cannot be already spinlocked.
	 */
	bh_lock_sock(sk);
	inet->tos = ip_hdr(skb)->tos;
	sk->sk_priority = skb->priority;
	sk->sk_protocol = ip_hdr(skb)->protocol;
	sk->sk_bound_dev_if = arg->bound_dev_if;
	ip_append_data(sk, ip_reply_glue_bits, arg->iov->iov_base, len, 0,
		       &ipc, &rt, MSG_DONTWAIT);
	if ((skb = skb_peek(&sk->sk_write_queue)) != NULL) {
		if (arg->csumoffset >= 0)
			*((__sum16 *)skb_transport_header(skb) +
			  arg->csumoffset) = csum_fold(csum_add(skb->csum,
								arg->csum));
		skb->ip_summed = CHECKSUM_NONE;
		ip_push_pending_frames(sk);
	}

	bh_unlock_sock(sk);

	ip_rt_put(rt);
}

void __init ip_init(void)
{
	ip_rt_init();//初始化路由表 fib
	inet_initpeers();//初始化用于管理ip端点的基础架构

#if defined(CONFIG_IP_MULTICAST) && defined(CONFIG_PROC_FS)
	igmp_mc_proc_init();
#endif
}

EXPORT_SYMBOL(ip_generic_getfrag);
EXPORT_SYMBOL(ip_queue_xmit);
EXPORT_SYMBOL(ip_send_check);
