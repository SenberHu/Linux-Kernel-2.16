/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The options processing module for ip.c
 *
 * Authors:	A.N.Kuznetsov
 *
 */

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/cipso_ipv4.h>

/*
 * Write options to IP header, record destination address to
 * source route option, address of outgoing interface
 * (we should already know it, so that this  function is allowed be
 * called only after routing decision) and timestamp,
 * if we originate this datagram.
 *
 * daddr is real destination address, next hop is recorded in IP header.
 * saddr is address of outgoing interface.
 */

void ip_options_build(struct sk_buff * skb, struct ip_options * opt,
			    __be32 daddr, struct rtable *rt, int is_frag)
{
	unsigned char *iph = skb_network_header(skb);

	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
	opt = &(IPCB(skb)->opt);

	if (opt->srr)
		memcpy(iph+opt->srr+iph[opt->srr+1]-4, &daddr, 4);

	if (!is_frag) {
		if (opt->rr_needaddr)
			ip_rt_get_source(iph+opt->rr+iph[opt->rr+2]-5, rt);
		if (opt->ts_needaddr)
			ip_rt_get_source(iph+opt->ts+iph[opt->ts+2]-9, rt);
		if (opt->ts_needtime) {
			struct timespec tv;
			__be32 midtime;
			getnstimeofday(&tv);
			midtime = htonl((tv.tv_sec % 86400) * MSEC_PER_SEC + tv.tv_nsec / NSEC_PER_MSEC);
			memcpy(iph+opt->ts+iph[opt->ts+2]-5, &midtime, 4);
		}
		return;
	}
	if (opt->rr) {
		memset(iph+opt->rr, IPOPT_NOP, iph[opt->rr+1]);
		opt->rr = 0;
		opt->rr_needaddr = 0;
	}
	if (opt->ts) {
		memset(iph+opt->ts, IPOPT_NOP, iph[opt->ts+1]);
		opt->ts = 0;
		opt->ts_needaddr = opt->ts_needtime = 0;
	}
}

/*
 * Provided (sopt, skb) points to received options,
 * build in dopt compiled option set appropriate for answering.
 * i.e. invert SRR option, copy anothers,
 * and grab room in RR/TS options.
 *
 * NOTE: dopt cannot point to skb.
 */

int ip_options_echo(struct ip_options * dopt, struct sk_buff * skb)
{
	struct ip_options *sopt;
	unsigned char *sptr, *dptr;
	int soffset, doffset;
	int	optlen;
	__be32	daddr;

	memset(dopt, 0, sizeof(struct ip_options));

	sopt = &(IPCB(skb)->opt);

	if (sopt->optlen == 0) {
		dopt->optlen = 0;
		return 0;
	}

	sptr = skb_network_header(skb);
	dptr = dopt->__data;

	daddr = skb_rtable(skb)->rt_spec_dst;

	if (sopt->rr) {
		optlen  = sptr[sopt->rr+1];
		soffset = sptr[sopt->rr+2];
		dopt->rr = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->rr, optlen);
		if (sopt->rr_needaddr && soffset <= optlen) {
			if (soffset + 3 > optlen)
				return -EINVAL;
			dptr[2] = soffset + 4;
			dopt->rr_needaddr = 1;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->ts) {
		optlen = sptr[sopt->ts+1];
		soffset = sptr[sopt->ts+2];
		dopt->ts = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->ts, optlen);
		if (soffset <= optlen) {
			if (sopt->ts_needaddr) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				dopt->ts_needaddr = 1;
				soffset += 4;
			}
			if (sopt->ts_needtime) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				if ((dptr[3]&0xF) != IPOPT_TS_PRESPEC) {
					dopt->ts_needtime = 1;
					soffset += 4;
				} else {
					dopt->ts_needtime = 0;

					if (soffset + 8 <= optlen) {
						__be32 addr;

						memcpy(&addr, sptr+soffset-1, 4);
						if (inet_addr_type(dev_net(skb_dst(skb)->dev), addr) != RTN_LOCAL) {
							dopt->ts_needtime = 1;
							soffset += 8;
						}
					}
				}
			}
			dptr[2] = soffset;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->srr) {
		unsigned char * start = sptr+sopt->srr;
		__be32 faddr;

		optlen  = start[1];
		soffset = start[2];
		doffset = 0;
		if (soffset > optlen)
			soffset = optlen + 1;
		soffset -= 4;
		if (soffset > 3) {
			memcpy(&faddr, &start[soffset-1], 4);
			for (soffset-=4, doffset=4; soffset > 3; soffset-=4, doffset+=4)
				memcpy(&dptr[doffset-1], &start[soffset-1], 4);
			/*
			 * RFC1812 requires to fix illegal source routes.
			 */
			if (memcmp(&ip_hdr(skb)->saddr,
				   &start[soffset + 3], 4) == 0)
				doffset -= 4;
		}
		if (doffset > 3) {
			memcpy(&start[doffset-1], &daddr, 4);
			dopt->faddr = faddr;
			dptr[0] = start[0];
			dptr[1] = doffset+3;
			dptr[2] = 4;
			dptr += doffset+3;
			dopt->srr = dopt->optlen + sizeof(struct iphdr);
			dopt->optlen += doffset+3;
			dopt->is_strictroute = sopt->is_strictroute;
		}
	}
	if (sopt->cipso) {
		optlen  = sptr[sopt->cipso+1];
		dopt->cipso = dopt->optlen+sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->cipso, optlen);
		dptr += optlen;
		dopt->optlen += optlen;
	}
	while (dopt->optlen & 3) {
		*dptr++ = IPOPT_END;
		dopt->optlen++;
	}
	return 0;
}

/*
 *	Options "fragmenting", just fill options not
 *	allowed in fragments with NOOPs.
 *	Simple and stupid 8), but the most efficient way.
 */
//修改第一个片段的ip报头 使其后续片段循环利用
void ip_options_fragment(struct sk_buff * skb)
{
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	struct ip_options * opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

    //l是选项列表的长度 
	while (l > 0) 
	{
		switch (*optptr) 
		{
		case IPOPT_END://遇到结束字符 则选项结束 退出
			return;
		case IPOPT_NOOP://遇到空 则选项长度递减  指向选项的指针指向下一个字节
			l--;
			optptr++;
			continue;
		}
		
		optlen = optptr[1];//获得该选项的长度,并价差合法性
		if (optlen<2 || optlen>l)
		  return;
		
		//是否设置了复制标志位
		if (!IPOPT_COPIED(*optptr))
			memset(optptr, IPOPT_NOOP, optlen);//若没有设置复制标志 则用NOOP填充
		//移到吓一跳选项
		l -= optlen;
		optptr += optlen;
	}
	opt->ts = 0;
	opt->rr = 0;
	opt->rr_needaddr = 0;
	opt->ts_needaddr = 0;
	opt->ts_needtime = 0;
	return;
}

/*
 * Verify options and fill pointers in struct options.
 * Caller should clear *opt, and set opt->data.
 * If opt == NULL, then skb->data should point to IP header.
 */
 //用来解读ip选项  分析报文头的一群选项  只负责解析将解析结果存放在ip_options{}结构中 不负责处理
 /*
  下面函数的两条执行路径:
  ip_options_get()->ip_options_get_finish()->ip_options_compile()
  ip_rcv_finish()->ip_rcv_options()->ip_options_compile()
在入口封包中 skb不为NULL
封包正在被传输: skb为NULL
*/
int ip_options_compile(struct net *net, struct ip_options * opt, struct sk_buff * skb)
{
	int l;
	unsigned char * iph;
	unsigned char * optptr;
	int optlen;
	unsigned char * pp_ptr = NULL;
	struct rtable *rt = NULL;

    //让optptr指向选项的开始
    //对于接收路径ip_rcv_finish->ip_options_compile skb显然不为NULL
	if (skb != NULL) 
	{
		rt = skb_rtable(skb);
		optptr = (unsigned char *)&(ip_hdr(skb)[1]);
	} 
	else
		optptr = opt->__data; 
	
	iph = optptr - sizeof(struct iphdr);

    //在循环中迭代所有的选项
	for (l = opt->optlen; l > 0; ) 
	{
		switch (*optptr) 
		{
		    
		    case IPOPT_END://类型为 选项结束,表明到达了选项表的末尾
		                   //将后续的字节全都变为IPOPT_END 
        		for (optptr++, l--; l>0; optptr++, l--) 
        		{
        			if (*optptr != IPOPT_END) {
        				*optptr = IPOPT_END;
						//设置标志 说明ipv4头发生了改变 需要重新生成校验和 
        				opt->is_changed = 1;
        			}
        		}
        		goto eol;
				
		    case IPOPT_NOOP://类型为 空选项  接着看下一个字节
			    l--;
			    optptr++;
			continue;
		}

		//取得第二个字节上放置的选项长度
		optlen = optptr[1];
		
        //检查选项长度是否合法值,只有IPOPT_END和IPOPT_NOOP为单字节选项,其余至少为2个字节
        //选项长度不能大于最大选项长度值
		if (optlen<2 || optlen>l) 
		{
			pp_ptr = optptr;//使pp_ptr指向错误的原因 并退出
			goto error;
		}
		
		switch (*optptr) 
		{
		    case IPOPT_SSRR://严格源路由
		    case IPOPT_LSRR://宽松源路由

				//选项长度至少为3字节  选项类型 选项长度和偏移量
     			if (optlen < 3)
     			{
     				pp_ptr = optptr + 1;
     				goto error;
     			}

				//optptr[2]放的是选项指针即偏移量 也就是选项的起始处
				//不能够小于4 因为前三个字节用于 type len offset
     			if (optptr[2] < 4) 
				{
     				pp_ptr = optptr + 2;
     				goto error;
     			}
				
     			/* NB: cf RFC-1812 5.2.4.1 */
     			if (opt->srr) //防止相同的选项
				{
     				pp_ptr = optptr;
     				goto error;
     			}
				
     			if (!skb)//若为传输包 
				{
     				if (optptr[2] != 4 || optlen < 7 || ((optlen-3) & 3)) 
					{
     					pp_ptr = optptr + 1;
     					goto error;
     				}
					//把第一个地址放入opt->faddr中
     				memcpy(&opt->faddr, &optptr[3], 4);
     				if (optlen > 7)//将后续的地址前移 
     					memmove(&optptr[3], &optptr[7], optlen-7);
     			}
				
     			opt->is_strictroute = (optptr[0] == IPOPT_SSRR);//是否为严格源路由
     			opt->srr = optptr - iph;
     			break;

				
     		    case IPOPT_RR:
     			if (opt->rr) //防止相同的选项
				{
     				pp_ptr = optptr;
     				goto error;
     			}

				//记录路由最少为3字节 
				/*    0            1             2
                 ---------------------------------------- -------
                  (选项类型) |  (选项长度)  |  (偏移量) |
                 ------------------------------------------------
                                   ... 
                 ------------------------------------------------
				*/  
				if (optlen < 3) 
				{
     				pp_ptr = optptr + 1;
     				goto error;
     			}

			    //偏移量至少为4  因为存储地址列表而保留的地址空间的前面至少有3个字节(选项类型 选项长度 指针)
     			if (optptr[2] < 4) {
     				pp_ptr = optptr + 2;
     				goto error;
     			}

				//偏移量不应该大于选项总长度
     			if (optptr[2] <= optlen)
				{
				    //偏移量与开头的3个字节之和 超过了选项长度 说明出现错误
     				if (optptr[2]+3 > optlen) {
     					pp_ptr = optptr + 2;
     					goto error;
     				}
     				if (skb) 
					{
					    //将ipv4地址复制到路由缓冲区
     					memcpy(&optptr[optptr[2]-1], &rt->rt_spec_dst, 4);
     					opt->is_changed = 1;//ipv4头发生了变化  需要重进计算校验和
     				}

					//如果地址没在此处写入 将在rr_needaddr被设置后被写入记录地址
					//但偏移量都会增加4，在ip_forward_options中会回走四字节在写入 
     				optptr[2] += 4;//将偏移量加4 指向下一个地址
     				opt->rr_needaddr = 1; //ip_forward_options将检查这个标志                   
     			}
     			opt->rr = optptr - iph;
     			break;
				
		    case IPOPT_TIMESTAMP://时间戳选项
			if (opt->ts) { //防止解析相同选项
				pp_ptr = optptr;
				goto error;
			}
    
	    	//时间戳选项至少为四字节
	    	/* 0             1          2           3
	    	----------------------------------------------------------- 
            (选项类型) | (选项长度) | (偏移量) |  (溢出计数器|标志位) |
            -----------------------------------------------------------
                                ....
            -----------------------------------------------------------
            溢出计数器:每跳在没有足够的空间后 就会加1
            标志位: 只包含时间戳   包含时间戳和地址  只包含指定跳的时间戳
            */
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}

			//偏移量最少为5 前面有四字节被占用
			if (optptr[2] < 5) {
				pp_ptr = optptr + 2;
				goto error;
			}

		    //偏移量不能大于选项总长度  否则为溢出	
			if (optptr[2] <= optlen) 
			{
				__be32 *timeptr = NULL;
				if (optptr[2]+3 > optptr[1]) {
					pp_ptr = optptr + 2;
					goto error;
				}
				
				switch(optptr[3]&0xF)//第四个字节的后四位 即标志位 
				{
				     case IPOPT_TS_TSONLY: //只包含时间戳
					opt->ts = optptr - iph;
					if (skb)
						timeptr = (__be32*)&optptr[optptr[2]-1];
					opt->ts_needtime = 1;
					optptr[2] += 4;
					break;
				      case IPOPT_TS_TSANDADDR://包含时间戳和地址
					if (optptr[2]+7 > optptr[1]) {
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					if (skb) 
					{
						memcpy(&optptr[optptr[2]-1], &rt->rt_spec_dst, 4);
						timeptr = (__be32*)&optptr[optptr[2]+3];
					}
					opt->ts_needaddr = 1; //是否需要记录地址
					opt->ts_needtime = 1; //是否需要设置时间戳
					optptr[2] += 8;
					break;
				    case IPOPT_TS_PRESPEC://只包含指定跳的时间戳
					if (optptr[2]+7 > optptr[1]) 
					{
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					{
						__be32 addr;
						memcpy(&addr, &optptr[optptr[2]-1], 4);

					    //检查地址类型 
						if (inet_addr_type(net, addr) == RTN_UNICAST)
							break;
						if (skb)
							timeptr = (__be32*)&optptr[optptr[2]+3];
					}
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				      default:
					if (!skb && !capable(CAP_NET_RAW)) {
						pp_ptr = optptr + 3;
						goto error;
					}
					break;
				}
				if (timeptr) {
					struct timespec tv;
					__be32  midtime;
					getnstimeofday(&tv);
					midtime = htonl((tv.tv_sec % 86400) * MSEC_PER_SEC + tv.tv_nsec / NSEC_PER_MSEC);
					memcpy(timeptr, &midtime, sizeof(__be32));
					opt->is_changed = 1;
				}
			} 
			else 
			{
				unsigned overflow = optptr[3]>>4;
				if (overflow == 15) {
					pp_ptr = optptr + 3;
					goto error;
				}
				opt->ts = optptr - iph;
				if (skb) {
					optptr[3] = (optptr[3]&0xF)|((overflow+1)<<4);
					opt->is_changed = 1;
				}
			}
			break;

			//处理路由警告
		    case IPOPT_RA:
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] == 0 && optptr[3] == 0)
				opt->router_alert = optptr - iph;
			break;

			
		    case IPOPT_CIPSO:
			if ((!skb && !capable(CAP_NET_RAW)) || opt->cipso) {
				pp_ptr = optptr;
				goto error;
			}
			opt->cipso = optptr - iph;
			if (cipso_v4_validate(skb, &optptr)) {
				pp_ptr = optptr;
				goto error;
			}
			break;

			
		      case IPOPT_SEC:
		      case IPOPT_SID:
		      default:
			if (!skb && !capable(CAP_NET_RAW)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		}
		l -= optlen;
		optptr += optlen;
	}

eol:
	if (!pp_ptr)
		return 0;

error:
	//如果为接收路径 则发送icmp错误消息
	if (skb) 
	{   
	    //发送icmp参数错误 
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((pp_ptr-iph)<<24));
	}
	return -EINVAL;
}


/*
 *	Undo all the changes done by ip_options_compile().
 */

void ip_options_undo(struct ip_options * opt)
{
	if (opt->srr) {
		unsigned  char * optptr = opt->__data+opt->srr-sizeof(struct  iphdr);
		memmove(optptr+7, optptr+3, optptr[1]-7);
		memcpy(optptr+3, &opt->faddr, 4);
	}
	if (opt->rr_needaddr) {
		unsigned  char * optptr = opt->__data+opt->rr-sizeof(struct  iphdr);
		optptr[2] -= 4;
		memset(&optptr[optptr[2]-1], 0, 4);
	}
	if (opt->ts) {
		unsigned  char * optptr = opt->__data+opt->ts-sizeof(struct  iphdr);
		if (opt->ts_needtime) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
			if ((optptr[3]&0xF) == IPOPT_TS_PRESPEC)
				optptr[2] -= 4;
		}
		if (opt->ts_needaddr) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
		}
	}
}

static struct ip_options *ip_options_get_alloc(const int optlen)
{
	return kzalloc(sizeof(struct ip_options) + ((optlen + 3) & ~3),
		       GFP_KERNEL);
}

static int ip_options_get_finish(struct net *net, struct ip_options **optp,
				 struct ip_options *opt, int optlen)
{
	while (optlen & 3)
		opt->__data[optlen++] = IPOPT_END;
	
	opt->optlen = optlen;
	if (optlen && ip_options_compile(net, opt, NULL)) {
		kfree(opt);
		return -EINVAL;
	}
	kfree(*optp);
	*optp = opt;
	return 0;
}
//此方法负责设置IP_OPTIONS调用系统调用setsockopt来从用户空间获得ip选项
int ip_options_get_from_user(struct net *net, struct ip_options **optp,
			     unsigned char __user *data, int optlen)
{
	struct ip_options *opt = ip_options_get_alloc(optlen);

	if (!opt)
		return -ENOMEM;
	if (optlen && copy_from_user(opt->__data, data, optlen)) {
		kfree(opt);
		return -EFAULT;
	}
	return ip_options_get_finish(net, optp, opt, optlen);
}

int ip_options_get(struct net *net, struct ip_options **optp,
		   unsigned char *data, int optlen)
{
	struct ip_options *opt = ip_options_get_alloc(optlen);

	if (!opt)
		return -ENOMEM;
	if (optlen)
		memcpy(opt->__data, data, optlen);
	return ip_options_get_finish(net, optp, opt, optlen);
}

void ip_forward_options(struct sk_buff *skb)
{
	struct   ip_options * opt	= &(IPCB(skb)->opt);
	unsigned char * optptr;
	struct rtable *rt = skb_rtable(skb);
	unsigned char *raw = skb_network_header(skb);

    //是否需要记录路由  对转发路由进行记录
	if (opt->rr_needaddr) 
	{  
	    //寻址到ip选项记录路由的起始处
		optptr = (unsigned char *)raw + opt->rr;

		//optptr[2]存在是数据的偏移量记录着存在数据字节数
		ip_rt_get_source(&optptr[optptr[2]-5], rt);
		opt->is_changed = 1;
	}
	if (opt->srr_is_hit) 
	{
		int srrptr, srrspace;

		optptr = raw + opt->srr;

		for ( srrptr=optptr[2], srrspace = optptr[1];
		     srrptr <= srrspace;
		     srrptr += 4
		     ) {
			if (srrptr + 3 > srrspace)
				break;
			if (memcmp(&rt->rt_dst, &optptr[srrptr-1], 4) == 0)
				break;
		}
		if (srrptr + 3 <= srrspace) {
			opt->is_changed = 1;
			ip_rt_get_source(&optptr[srrptr-1], rt);
			ip_hdr(skb)->daddr = rt->rt_dst;
			optptr[2] = srrptr+4;
		} else if (net_ratelimit())
			printk(KERN_CRIT "ip_forward(): Argh! Destination lost!\n");
		if (opt->ts_needaddr) {
			optptr = raw + opt->ts;
			ip_rt_get_source(&optptr[optptr[2]-9], rt);
			opt->is_changed = 1;
		}
	}
	if (opt->is_changed) {
		opt->is_changed = 0;
		ip_send_check(ip_hdr(skb));
	}
}

//处理松散源路由
int ip_options_rcv_srr(struct sk_buff *skb)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	int srrspace, srrptr;
	__be32 nexthop;
	struct iphdr *iph = ip_hdr(skb);
	unsigned char *optptr = skb_network_header(skb) + opt->srr;
	struct rtable *rt = skb_rtable(skb);
	struct rtable *rt2;
	int err;
	
	if (!opt->srr)
		return 0;

	if (skb->pkt_type != PACKET_HOST)
		return -EINVAL;
	if (rt->rt_type == RTN_UNICAST) {
		if (!opt->is_strictroute)
			return 0;
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl(16<<24));
		return -EINVAL;
	}
	if (rt->rt_type != RTN_LOCAL)
		return -EINVAL;

    //迭代源路由地址列表
	for (srrptr=optptr[2], srrspace = optptr[1]; srrptr <= srrspace; srrptr += 4) {
		if (srrptr + 3 > srrspace) {
			icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((opt->srr+2)<<24));
			return -EINVAL;
		}
		memcpy(&nexthop, &optptr[srrptr-1], 4);

		rt = skb_rtable(skb);
		skb_dst_set(skb, NULL);
		err = ip_route_input(skb, nexthop, iph->saddr, iph->tos, skb->dev);
		rt2 = skb_rtable(skb);
		if (err || (rt2->rt_type != RTN_UNICAST && rt2->rt_type != RTN_LOCAL)) {
			ip_rt_put(rt2);
			skb_dst_set(skb, &rt->u.dst);
			return -EINVAL;
		}
		ip_rt_put(rt);
		if (rt2->rt_type != RTN_LOCAL)
			break;
		/* Superfast 8) loopback forward */
		//设置下一跳地址
		memcpy(&iph->daddr, &optptr[srrptr-1], 4);
		opt->is_changed = 1;
	}

	if (srrptr <= srrspace) 
	{
		opt->srr_is_hit = 1;//设置本机标志
		opt->is_changed = 1;//iPv4头发生了变化
	}
	return 0;
}
