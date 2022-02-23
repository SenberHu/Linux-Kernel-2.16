/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP forwarding functionality.
 *
 * Authors:	see ip.c
 *
 * Fixes:
 *		Many		:	Split from ip.c , see ip_input.c for
 *					history.
 *		Dave Gregorich	:	NULL ip_rt_put fix for multicast
 *					routing.
 *		Jos Vos		:	Add call_out_firewall before sending,
 *					use output device for accounting.
 *		Jos Vos		:	Call forward firewall after routing
 *					(always use output device).
 *		Mike McLagan	:	Routing by source
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>

static int ip_forward_finish(struct sk_buff *skb)
{
	struct ip_options * opt	= &(IPCB(skb)->opt);

	IP_INC_STATS_BH(dev_net(skb_dst(skb)->dev), IPSTATS_MIB_OUTFORWDATAGRAMS);

    //对ip选项进行处理
	if (unlikely(opt->optlen))
		ip_forward_options(skb);

	return dst_output(skb);
}

//进行转发的主程序处理方法
int ip_forward(struct sk_buff *skb)
{
	struct iphdr *iph;	/* Our header */
	struct rtable *rt;	/* Route we use */
	struct ip_options * opt	= &(IPCB(skb)->opt);

	//将LRO(Large Received Offload)数据包丢弃,LRO是一种性能优化技术 将多个数据包合并成大型SKB 然后传给上层,
	//减少CPU开销,但它不能被转发 它的大小超过了出口的mtu值,GRO支持转发 但LRO不支持转发
	if (skb_warn_if_lro(skb))
		goto drop;

	 //进行ipSec策略检查
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb))
		goto drop;

    //如果设置了router_alert(路由警告信息)选项 则必须调用ip_call_ra_chain来处理数据包
    //对原始套接字调用setsockopts()使用IP_ROUTER_ALERT 该套接字被加入到ip_ra_chain中,ip_call_ra_chain
    //会将数据包交给所有的原始套接字
	if (IPCB(skb)->opt.router_alert && ip_call_ra_chain(skb))
		return NET_RX_SUCCESS;

	//数据包MAC地址类型不是发往本地的则丢弃
	//pkt_type是由eth_type_trans来确定的
	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	//现在运作在L3层 不必担心L4层的校验工作 用CHECKSUM_NONE指出当前校验和无误
	skb_forward_csum(skb);

	/*
	 *	According to the RFC, we must first decrease the TTL field. If
	 *	that reaches zero, we must reply an ICMP control message telling
	 *	that the packet's lifetime expired.
	 */
	 //当TTL减少为0后 表明应该将数据报丢弃
	if (ip_hdr(skb)->ttl <= 1)
		goto too_many_hops;

	if (!xfrm4_route_forward(skb))
		goto drop;

	//从skb->_skb_dst获得路由项
	rt = skb_rtable(skb);

	//设置了严格路由 并且目的地址和网管地址不一致
	if (opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto sr_failed;

	if (unlikely(skb->len > dst_mtu(&rt->u.dst) && //检查包的大小 是否大于外出设备的MTU值 
		!skb_is_gso(skb) && //不是gso
		(ip_hdr(skb)->frag_off & htons(IP_DF))) &&//检查ip头部DF不准分片是否设置 
		!skb->local_df  //不能进行本地切片
	   ) 
    {
        //增加统计信息
		IP_INC_STATS(dev_net(rt->u.dst.dev), IPSTATS_MIB_FRAGFAILS);

		//发送icmp消息  目的不可达--->需要进行分片
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			      htonl(dst_mtu(&rt->u.dst)));
		goto drop;
	}

	/* We are about to mangle packet. Copy it! */
	//我们即将修改包 先复制它
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->u.dst.dev)+rt->u.dst.header_len))
		goto drop;  

	//获得ip头
	iph = ip_hdr(skb);

	/* Decrease ttl after skb cow done */
    //减小ip头中的ttl
	ip_decrease_ttl(iph);

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */
	//发送一条icmp重定向消息
	//检查是否设置了RTCF_DOREDIRECT标志  在__mkroute_input进行设置
	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr && !skb_sec_path(skb))
		ip_rt_send_redirect(skb);

	//在ip_queue_xmit中设置优先级为套接字的优先级 在转发时候没有套接字优先级
	//根基表ip_tos2prio 来设置优先级
	skb->priority = rt_tos2priority(iph->tos);

    //netfileter钩子 执行完后 若继续执行 将执行ip_forward_finish
	return NF_HOOK(PF_INET, NF_INET_FORWARD, skb, skb->dev, rt->u.dst.dev,
		       ip_forward_finish);

sr_failed:
	/*
	 *	Strict routing permits no gatewaying
	 */
     //发送icmp消息 目的不可达--源路由失败 消息
	 icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
	 goto drop;

too_many_hops:
	/* Tell the sender its packet died... */

	//增加SNMP计数器InHdrErrors的值
	IP_INC_STATS_BH(dev_net(skb_dst(skb)->dev), IPSTATS_MIB_INHDRERRORS);

	//发送 超时---TTL超时 icmp消息
	icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
