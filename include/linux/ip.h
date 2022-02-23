/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP protocol.
 *
 * Version:	@(#)ip.h	1.0.2	04/28/93
 *
 * Authors:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_IP_H
#define _LINUX_IP_H
#include <linux/types.h>
#include <asm/byteorder.h>

#define IPTOS_TOS_MASK		0x1E  //0001 1110
#define IPTOS_TOS(tos)		((tos)&IPTOS_TOS_MASK)
#define	IPTOS_LOWDELAY		0x10
#define	IPTOS_THROUGHPUT	0x08
#define	IPTOS_RELIABILITY	0x04
#define	IPTOS_MINCOST		0x02

#define IPTOS_PREC_MASK		0xE0
#define IPTOS_PREC(tos)		((tos)&IPTOS_PREC_MASK)
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00


/*
0    1        3            8                               31
------------------------------------------------------------
|复制|选项类别|  选项号    |                               | 
|标志|        |            |                           ~~  |
------------------------------------------------------------
复制标志:
   0仅在第一个分片中复制,  1复制到所有分片,通过IPOPT_COPIED()宏可以取出值
选项类别: 通过IPOPT_CLASS()宏可以取出值
   00:数据报控制  IPOPT_CONTROL
   01:保留　　　　IPOPT_RESERVED1　
   10:调试测量    IPOPT_MEASUREMENT 
   11:保留　　　　IPOPT_RESERVED2　 　
选项号:通过IPOPT_NUMBER()宏可以取出值
   00000:0  选项结束                  IPOPT_END
   00001:1  无操作                    IPOPT_NOOP
   00010:2  安全                      IPOPT_SEC
   00011:3  不严格的源路由            IPOPT_LSRR
   00100:4  时间戳                    IPOPT_TIMESTAMP
   00110:6  商用Internet协议安全选项  IPOPT_CIPSO        
   00111:7  记录路由                  IPOPT_RR 
   01000:8  流ID                      IPOPT_SID
   01001:9  严格源路由                IPOPT_SSRR
   10100:20 路由器警告                IPOPT_RA
*/
/* IP options */
#define IPOPT_COPY		0x80 //复制到所有分片
#define IPOPT_CLASS_MASK	0x60
#define IPOPT_NUMBER_MASK	0x1f

#define	IPOPT_COPIED(o)		((o)&IPOPT_COPY) //取出copy字段 即8bit中的第一位
#define	IPOPT_CLASS(o)		((o)&IPOPT_CLASS_MASK)//取出第二位和第三位(类别)
#define	IPOPT_NUMBER(o)		((o)&IPOPT_NUMBER_MASK)//取出第四位到第八位编号

#define	IPOPT_CONTROL		0x00 //0 00 00000数据报控制
#define	IPOPT_RESERVED1		0x20 //0 01 00000保留字段
#define	IPOPT_MEASUREMENT	0x40// 0 10 00000 调试测试使用
#define	IPOPT_RESERVED2		0x60// 0 11 00000 保留字段


/*选项结束也是1字节选项,用于选项字段结束时的填充,只能用于最后一个选项,并且只能用一次*/
#define IPOPT_END	(0 |IPOPT_CONTROL)//0 00 00000  选项结束  //单字节选项  不需要长度和值


/*无操作是1字节的选项,主要用于选项和选项之间的填充符,使下一个选项在16位或32位边界上对齐*/
#define IPOPT_NOOP	(1 |IPOPT_CONTROL)//0 00 00001  无操作    //单子节选项   不需要长度和值

/*安全级别选项*/
#define IPOPT_SEC	(2 |IPOPT_CONTROL|IPOPT_COPY) // 1 00 00010 复制到所有分片 数据报控制   [安全级别]   多字节选项包含长度和值

/*在传送过程中，一台中间路由可以使用另一台路由器（不再列表中），作为通向列表中下一个路由器的路径*/
#define IPOPT_LSRR	(3 |IPOPT_CONTROL|IPOPT_COPY)//  1 00 00011 复制到所有分片 数据报控制  [松散源路由] 多字节选项包含长度和值

/*                                        7 6 5 4 3 2 1 0 
---------------------------------------------------------- 
| <复制,class,number> |   长度   |  值    | oflw  |  flg |
---------------------------------------------------------- 
                         ip地址  |                        
---------------------------------------------------------- 
                         时间戳  |                        
---------------------------------------------------------- 
oflw字段表示由于缺少空间而无法记录时间戳的主机数目 最多表示15个主机则会溢出
flg:决定改选项的工作方式 
 0 只记录时间戳 每个时间戳按4字节连续排放 最多37/4=9个
 1 同时记录ip地址和时间戳  37/8 = 4 个网关信息
 3 存放ip地址和时间戳  ip地址是源端预先填入的 当网关地址与预先填入的地址相同时，网管填入转发时间戳
*/
#define IPOPT_TIMESTAMP	(4 |IPOPT_MEASUREMENT)//     0 10 00100 不复制到所有分片 排错管理  [时间戳]         多字节选项包含长度和值
#define IPOPT_CIPSO	(6 |IPOPT_CONTROL|IPOPT_COPY)//  1 00 00110 复制到所有分片 数据报控制  

/*记录路由选项用来记录处理数据报的因特网路由器.它可以列出最多九个路由器IP地址
-------------------------------------------------
|   <复制,class,number> |   长度    |     值    |
|         T             |    L      |      v    |
-------------------------------------------------
|第一个ip                                       | 
-------------------------------------------------
|。。。。                                       |
-------------------------------------------------
|最后一个ip                                     |
-------------------------------------------------
9*4+1+1+1=39字节
*/
#define IPOPT_RR	(7 |IPOPT_CONTROL)           //  0 00 00111 不复制到所有分片 记录路由 [ ]               多字节选项包含长度和值



//对于不支持流工作方式的网络，该选项提供一种机制通过传送16bit流标识符来模拟流工作方式
#define IPOPT_SID	(8 |IPOPT_CONTROL|IPOPT_COPY)//  1 00 01000 复制到所有分片 数据报控制 [流标致符 ]               多字节选项包含长度和值

/*传送者必须列出路径上每台路由器的IP地址，而且沿途都不能修改，必须按照列表上的路由地址进行传送*/
#define IPOPT_SSRR	(9 |IPOPT_CONTROL|IPOPT_COPY)//  1 00 01001 复制到所有分片 数据报控制 [严格路由]        多字节选项包含长度和值

////把封包标记成需要特殊处理，他试图为封包数据流建立更好的QoS。
//路由器警告  用于通知路由器对IP数据进行跟严格的内容检查
#define IPOPT_RA	(20|IPOPT_CONTROL|IPOPT_COPY)//  1 01 00000 复制到所有分片 数据报控制 [保留字段]        多字节选项包含长度和值

#define IPVERSION	4
#define MAXTTL		255
#define IPDEFTTL	64

#define IPOPT_OPTVAL 0
#define IPOPT_OLEN   1
#define IPOPT_OFFSET 2
#define IPOPT_MINOFF 4
#define MAX_IPOPTLEN 40
#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_EOL IPOPT_END
#define IPOPT_TS  IPOPT_TIMESTAMP

//用于时间戳 
#define	IPOPT_TS_TSONLY		0		/* timestamps only 只包含时间戳*/
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses 包含时间戳和地址*/
#define	IPOPT_TS_PRESPEC	3		/* specified modules only 只包含指定跳的时间戳*/

#define IPV4_BEET_PHMAXLEN 8

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4, //版本号
  		ihl:4;//首部长度  //以4字节为单位  首部最长: 15*4=60,固定为20字节 其他字节为ip选项
#else
#error	"Please fix <asm/byteorder.h>"
#endif
/*
     ---------------------------------
     |   |   |   | D | R | T | C |   |
     ---------------------------------
        优先级         TOS位
        
     D:最小时延
     R:最高可靠性
     T:最大吞吐量
     C:最小代价

     优先级:
     111 Network contorl
     110 Internetwork COntrol
     101 CRITIC /ECP	
     100 FLASH Override
     011 FLASH
     010 immediate
     001 priority
     000 routine
     当路由器出现拥塞而必须丢弃一些数据报时，具有低优先级的将首先被丢弃
     */
     __u8	tos;//服务类型

	
	__be16	tot_len;//总长度IP首部+ip数据 RFC791规定 最短不得少于576字节
	__be16	id;//标志码   用于数据包分片 当数据报大于MTU时候 数据报被分片，具有相同标志位字段的分片属于一个数据报

/*************************************************************
    -----------------
	|  CE | DF | MF |
    -----------------
        控制比特 3位
    bit 0:为1 表示拥塞
    bit 1:为0 表示数据报长度大并且超过MTU ，对其进行分片； 为1 表示不可进行分片
    bit 2:为0 表示这是最后一个分片 为1表示还有后续分片

    分片偏移:13位
    100:表示拥塞
    010:表示不分片
    001:表示后续还有其他分片 除最后一个分片 其余都应该设置此位
****************************************************************************/
	__be16	frag_off;//标志位和片偏移 单位为8字节
	__u8	ttl; //生存时间 每一个路由器处理需要转发的数据报时首先将该字段减1 若该字段变为0则丢弃它，并给数据报的起始端发送一个ICMP报文
	__u8	protocol;//IPPROTO_TCP协议类型
	__sum16	check;//首部校验和 仅为IP首部部分
	__be32	saddr;//源地址
	__be32	daddr;//目的地址
	/*The options start here. */
};
	
#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

static inline struct iphdr *ipip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_transport_header(skb);
}
#endif

struct ip_auth_hdr {
	__u8  nexthdr;
	__u8  hdrlen;		/* This one is measured in 32 bit units! */
	__be16 reserved;
	__be32 spi;
	__be32 seq_no;		/* Sequence number */
	__u8  auth_data[0];	/* Variable len but >=4. Mind the 64 bit alignment! */
};

struct ip_esp_hdr {
	__be32 spi;
	__be32 seq_no;		/* Sequence number */
	__u8  enc_data[0];	/* Variable len but >=8. Mind the 64 bit alignment! */
};

struct ip_comp_hdr {
	__u8 nexthdr;
	__u8 flags;
	__be16 cpi;
};

struct ip_beet_phdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 padlen;
	__u8 reserved;
};

#endif	/* _LINUX_IP_H */
