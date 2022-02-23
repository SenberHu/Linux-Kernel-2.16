#ifndef __LINUX_IF_PACKET_H
#define __LINUX_IF_PACKET_H

#include <linux/types.h>

struct sockaddr_pkt
{
	unsigned short spkt_family;
	unsigned char spkt_device[14];
	__be16 spkt_protocol;
};

struct sockaddr_ll
{
	unsigned short	sll_family;// 和sockaddr_in中的sa_family一样，地址族的意思
	__be16		sll_protocol;//表示上层的协议类型ETH_P_IP
	int		sll_ifindex;//表示接口类型
	unsigned short	sll_hatype; // ARP硬件地址类型
	unsigned char	sll_pkttype;//PACKET_HOST
	unsigned char	sll_halen;  //mac地址长度
	unsigned char	sll_addr[8];//为目的MAC地址
};

/* Packet types */

#define PACKET_HOST		0		/* To us		发送给本机的报文*/
#define PACKET_BROADCAST	1		/* To all		广播包*/
#define PACKET_MULTICAST	2		/* To group		2层组播地址*/
#define PACKET_OTHERHOST	3		/* 若转发机制使能 则进行转发.否则丢弃*/
#define PACKET_OUTGOING		4		//这个包将被发出
/* These ones are invisible by user level */
#define PACKET_LOOPBACK		5		/* 这个包发向loopback设备。由于有这个标记，在处理loopback设备室，内核可以跳过一些真实设备才需要的操作 */
#define PACKET_FASTROUTE	6		/* Fastrouted frame	这个包有快速路由代码查找路由。快速路由功能在2.6内核中已经去掉了*/

/* Packet socket options */

#define PACKET_ADD_MEMBERSHIP		1
#define PACKET_DROP_MEMBERSHIP		2
#define PACKET_RECV_OUTPUT		3
/* Value 4 is still used by obsolete turbo-packet. */
#define PACKET_RX_RING			5
#define PACKET_STATISTICS		6
#define PACKET_COPY_THRESH		7
#define PACKET_AUXDATA			8
#define PACKET_ORIGDEV			9
#define PACKET_VERSION			10
#define PACKET_HDRLEN			11
#define PACKET_RESERVE			12
#define PACKET_TX_RING			13
#define PACKET_LOSS			14

struct tpacket_stats
{
	unsigned int	tp_packets;
	unsigned int	tp_drops;
};

struct tpacket_auxdata
{
	__u32		tp_status;
	__u32		tp_len;
	__u32		tp_snaplen;
	__u16		tp_mac;
	__u16		tp_net;
	__u16		tp_vlan_tci;
};

/* Rx ring - header status */
#define TP_STATUS_KERNEL	0x0
#define TP_STATUS_USER		0x1
#define TP_STATUS_COPY		0x2
#define TP_STATUS_LOSING	0x4
#define TP_STATUS_CSUMNOTREADY	0x8

/* Tx ring - header status */
#define TP_STATUS_AVAILABLE	0x0
#define TP_STATUS_SEND_REQUEST	0x1
#define TP_STATUS_SENDING	0x2
#define TP_STATUS_WRONG_FORMAT	0x4

struct tpacket_hdr
{
	unsigned long	tp_status;
	unsigned int	tp_len;
	unsigned int	tp_snaplen;
	unsigned short	tp_mac;
	unsigned short	tp_net;
	unsigned int	tp_sec;
	unsigned int	tp_usec;
};

#define TPACKET_ALIGNMENT	16
#define TPACKET_ALIGN(x)	(((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
#define TPACKET_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + sizeof(struct sockaddr_ll))

struct tpacket2_hdr
{
	__u32		tp_status;
	__u32		tp_len;
	__u32		tp_snaplen;
	__u16		tp_mac;
	__u16		tp_net;
	__u32		tp_sec;
	__u32		tp_nsec;
	__u16		tp_vlan_tci;
};

#define TPACKET2_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket2_hdr)) + sizeof(struct sockaddr_ll))

enum tpacket_versions
{
	TPACKET_V1,
	TPACKET_V2,
};

/*
   Frame structure:

   - Start. Frame must be aligned to TPACKET_ALIGNMENT=16
   - struct tpacket_hdr
   - pad to TPACKET_ALIGNMENT=16
   - struct sockaddr_ll
   - Gap, chosen so that packet data (Start+tp_net) alignes to TPACKET_ALIGNMENT=16
   - Start+tp_mac: [ Optional MAC header ]
   - Start+tp_net: Packet data, aligned to TPACKET_ALIGNMENT=16.
   - Pad to align to TPACKET_ALIGNMENT=16
 */

struct tpacket_req
{
	unsigned int	tp_block_size;	/* Minimal size of contiguous block */
	unsigned int	tp_block_nr;	/* Number of blocks */
	unsigned int	tp_frame_size;	/* Size of frame */
	unsigned int	tp_frame_nr;	/* Total number of frames */
};

struct packet_mreq
{
	int		mr_ifindex;
	unsigned short	mr_type;
	unsigned short	mr_alen;
	unsigned char	mr_address[8];
};

#define PACKET_MR_MULTICAST	0
#define PACKET_MR_PROMISC	1
#define PACKET_MR_ALLMULTI	2
#define PACKET_MR_UNICAST	3

#endif
