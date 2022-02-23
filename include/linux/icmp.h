/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the ICMP protocol.
 *
 * Version:	@(#)icmp.h	1.0.3	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *

 该头文件定义ICMP首部以及ICMP的错误类型
 一个ICMP错误包括:类型(type)和代码(code),分别对应ICMP首部中的type和code字段
 
			   -------------------
			   |   ICMP报文段	 | 
			   ------------------- 
	  ----------------------------
	  | IP首部 |	IP数据		 |
	  ----------------------------
 ---------------------------------------
 | MAC| 	  数据帧			 | FCS |
 ---------------------------------------


 */
#ifndef _LINUX_ICMP_H
#define	_LINUX_ICMP_H

#include <linux/types.h>

//类型值定义
#define ICMP_ECHOREPLY		0	/* Echo Reply			echo回复应答报文 code为0*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	目的不可达*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		源端节制 此类型报文是源端为了缓解接收压力发送给本地通知,使其缓解发送速度*/
#define ICMP_REDIRECT		5	/* Redirect (change route)重定向报文	*/
#define ICMP_ECHO		    8	/* Echo Request			 echo回复报文 code为0*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded     时间超时*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem	参数错误	code取值一般为0 */
#define ICMP_TIMESTAMP		13	/* Timestamp Request	时间戳报文	code取值为0*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		时间戳应答报文 code取值为0*/
#define ICMP_INFO_REQUEST	15	/* Information Request	信息查询报文	*/
#define ICMP_INFO_REPLY		16	/* Information Reply	信息查询应答报文	*/
#define ICMP_ADDRESS		17	/* Address Mask Request		地址掩码请求*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		地址掩码请求应答*/
#define NR_ICMP_TYPES		18


//目的不可达具体的代码值
/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable	网络不可达	*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		主机不可达*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable	协议不可达	*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		端口不可达*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	需要分片但IP首部中的DF位置1*/
#define ICMP_SR_FAILED		5	/* Source Route failed		源路由失败*/
#define ICMP_NET_UNKNOWN	6  //目标网络未知
#define ICMP_HOST_UNKNOWN	7  //目标主机未知
#define ICMP_HOST_ISOLATED	8  //源主机被隔离
#define ICMP_NET_ANO		9  //与目标网络通信被强制禁止
#define ICMP_HOST_ANO		10 //与目标主机通信被强制禁止
#define ICMP_NET_UNR_TOS	11 //对于请求的服务类型TOS 网络不可达
#define ICMP_HOST_UNR_TOS	12 //对于请求的服务类型TOS 主机不可达
#define ICMP_PKT_FILTERED	13	/* Packet filtered 由于过滤 通信被强制禁止*/
#define ICMP_PREC_VIOLATION	14	/* Precedence violation 主机越权*/
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off 优先权终止生效*/
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

//重定位代码值
/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net		基于网络的重定向报文	*/
#define ICMP_REDIR_HOST		1	/* Redirect Host	基于主机的重定向报文	*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS	基于网络和服务类型的重定向报文*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS基于服务类型和主机的重定向报文	*/

//超时出错的代码值
/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded	传输中TTL超时	*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	分片组合时间超时(某个数据包的所有分片在规定时间未完全到达)
                                如果第一个分片尚未到达而此时发生超时,则不发送ICMP错误报文*/


struct icmphdr {
  __u8		type;//类型
  __u8		code;//代码
  __sum16	checksum;//校验和

  //根据类型和代码 可变的部分
  union {
	struct {
		__be16	id;
		__be16	sequence;
	} echo;
	__be32	gateway;
	struct {
		__be16	__unused;
		__be16	mtu;
	} frag;
  } un;
};

#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct icmphdr *icmp_hdr(const struct sk_buff *skb)
{
	return (struct icmphdr *)skb_transport_header(skb);
}
#endif

/*
 *	constants for (set|get)sockopt
 */

#define ICMP_FILTER			1

struct icmp_filter {
	__u32		data;
};


#endif	/* _LINUX_ICMP_H */
