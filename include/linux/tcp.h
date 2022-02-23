/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

//TCP_SYN_SENT状态转换
struct tcphdr {
	__be16	source; //发送端端口号  
	__be16	dest; //接收端 端口号
	__be32	seq; //序列号 本段发送数据包中所包含的第一个字节的序列号
	__be32	ack_seq; //一方面表示请求序列号  另一方面表示应答序列号
	                /*在远端开来 该字段含义为本地请求的下一个字节的序列号，也就是在此序列号之前的都已经被接收*/
#if defined(__LITTLE_ENDIAN_BITFIELD)//小端表示
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)//大端表示
	__u16	doff:4, //tcp首部长度以4字节为单位(包括TCP选项 如果存在) 也就是用户数据的开始起点
		res1:4, //保留
        //下面两个字段和ECN机制有关
		cwr:1,//拥塞窗口缩小标志		     
		ece:1,//Ecn-echo标志  
		  
		urg:1,//紧急指针字段  紧急数据是将接收到的数据立即传给应用程序
		ack:1,//为1表示此是个应答报文 应答报文一般都是随着数据一起发送的
		psh:1,//意义同URG 表示数据需要立刻交给应用程序 在软件上是给应用程序发送SIGURG信号
		rst:1,//复位标记  表示对方要求本地重新建立与对方的连接
		syn:1,//为1 建立连接时候的同步报文
		fin:1;//结束连接报文
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;//窗口大小 用于流控 表示当前对方所能容忍的最大数据接收量
	__sum16	check;//校验和
	__be16	urg_ptr;//紧急数据部分 是个偏移值 该偏移量是从包中第一个数据字节算起，只有urg为1的时候紧急指针字段才有效
};

/****
(1)选项结束 类型0
  --------
  00000000
  --------
(2)无操作选项 类型1  作为填充
  ---------
  00000001
  ---------
(3)最大报文长度 类型2
  ---------------------------------------------------------------------------
  00000010  |  00000100        |       最大报文长度(MSS)
  --------------------------------------------------------------------------
  类型2     长度4(包括类型1字节本身1字节和后面的数据部分)
  
最大报文长度指用户可以一次发送的数据最大长度
MSS = MTU-(TCP首部长度+IP首部长度)
*/


/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __cpu_to_be32(0x00800000),
	TCP_FLAG_ECE = __cpu_to_be32(0x00400000),
	TCP_FLAG_URG = __cpu_to_be32(0x00200000),
	TCP_FLAG_ACK = __cpu_to_be32(0x00100000),
	TCP_FLAG_PSH = __cpu_to_be32(0x00080000),
	TCP_FLAG_RST = __cpu_to_be32(0x00040000),
	TCP_FLAG_SYN = __cpu_to_be32(0x00020000),
	TCP_FLAG_FIN = __cpu_to_be32(0x00010000),
	TCP_RESERVED_BITS = __cpu_to_be32(0x0F000000),
	TCP_DATA_OFFSET = __cpu_to_be32(0xF0000000)
}; 

/* TCP socket options */
/*在使用一些协议通讯的时候，比如Telnet，会有一个字节字节的发送的情景，
每次发送一个字节的有用数据，就会产生41个字节长的分组，20个字节的IP Header 和 20个字节的TCP Header，
这就导致了1个字节的有用信息要浪费掉40个字节的头部信息，这是一笔巨大的字节开销，
而且这种Small packet在广域网上会增加拥塞的出现。
如果解决这种问题 Nagle就提出了一种通过减少需要通过网络发送包的数量来提高TCP/IP传输的效率，这就是Nagle算法*/
/*关闭Nagle's算法,Nagle算法主要是避免发送小的数据包，要求TCP连接上最多只能有一个未被确认的小分组，
在该分组的确认到达之前不能发送其他的小分组

setsockopt(sockfd,IPPROTO_TCP,TCP_NODELAY,&on,sizeof(on))
*/
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. (int)
                               nagle 算法的目的是减少广域网上小分组的数目       

                             */
#define TCP_MAXSEG		2	/* Limit MSS   设置最大分节大小 (int)*/ 
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u16	__tcpm_pad1;				/* zero */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad2;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32	ts_recent;	/* Time stamp to echo next		*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	来自对端通告的滑动窗口扩大因子,从来自对端的第一个SYN中获取*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	本地接收滑动窗口的扩大因子*/
/*	SACKs data	*/
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;  	/* mss requested by user in ioctl */
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

/* This is the max number of SACKS that we'll generate and process. It's safe
 * to increse this, although since:
 *   size = TCPOLEN_SACK_BASE_ALIGNED (4) + n * TCPOLEN_SACK_PERBLOCK (8)
 * only four options will fit in a standard TCP header */
#define TCP_NUM_SACKS 4

struct tcp_request_sock 
{
	struct inet_request_sock 	req;

#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	const struct tcp_request_sock_ops *af_specific;
#endif

    //客户端SYN段中携带的seq，即客户端的初始序列号
	u32			 	rcv_isn;

    //SYN+ACK段携带的seq，即服务器端的初始序列号
	u32			 	snt_isn;
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}


/******************
Sender缓冲区:
        --------------->snd_wnd<-------
---------------------------------------
Acked   |   NotAcked    |    Credit   |
---------------------------------------
     snd_una         snd_nxt         snd_una+snd_wnd

Receiver缓冲区:

--------------------------------------------
Acked    |     NotAcked     |    Credit    |
--------------------------------------------
      rcv_wup             rcv_nxt      rcv_wup+rcv_wnd 
*/

struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	
	u16	tcp_header_len;	     /* Bytes of tcp header to send	tcp头部长度*/
	u16	xmit_size_goal_segs; /* Goal for segmenting output packets 分段数据包的数量*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
    //头部预置位（用于检测头部标识位处理ACK和PUSH之外还有没有其他位，从而判断是不是可以使用快速路径处理数据
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
 	u32	rcv_nxt;	/* What we want to receive next 	希望接收的下一个序列号*/
	u32	copied_seq;	/* Head of yet unread data		应用程序下次从这里复制数据*/
	u32	rcv_wup;	/* rcv_nxt on last window update sent	记录滑动窗口的左边沿,落在滑动窗口中的最小的一个序号*/
    
	u32	snd_nxt;	/* Next sequence we send	下一个待发送的序列号	*/

 	u32	snd_una;	/* First byte we want an ack for	下一个待确认的字节*/
 	u32	snd_sml;	/* 已经发出去的最近的一个小包的最后一个字节*/
	                 
	u32	rcv_tstamp;	/*最后一次接收到ACK的时间戳 timestamp of last received ACK (for keepalives) */
	u32	lsndtime;	/* 最后一次发送数据包时间戳 timestamp of last sent data packet (for restart window) */

	/* Data for direct copy to user */
	// 注意下面这个ucopy：就是将用户数据从skb中拿出来放进去，然后传给应用进程！！！
	struct {
		struct sk_buff_head	prequeue;// 预处理队列
		struct task_struct	*task;// 预处理进程
		struct iovec		*iov;// 用户程序(应用程序)接收数据的缓冲区
		int			memory; // 用于预处理计数
		int			len;/// 预处理长度 
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	u32	snd_wl1;	/* Sequence for window update		*/
	u32	snd_wnd;	/* The window we expect to receive	*/

	//记录对方最大的发送 window 窗口值 
	u32	max_window;	/* Maximal window ever seen from peer	*/

	// 最长报文大小默认536, 与对方协商一般为1460 = 1500-20-20
	u32	mss_cache;	/* Cached effective mss, not including SACKS */

    //// 对外公布的最大的窗口
	u32	window_clamp;	/* Maximal window to advertise	表示滑动窗口的最大值,滑动窗口的大小在变化的过程中不能超出这个值*/

    // 当前窗口值 
	u32	rcv_ssthresh;	/* Current window clamp		是当前的接收窗口大小的一个阀值	*/

	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	u16	advmss;		/* Advertised MSS		接收端通告的MSS	*/
	u8	frto_counter;	/* Number of new acks after RTO */
	u8	nonagle;	/* Disable Nagle algorithm?             */

/* RTT measurement */
	u32	srtt;		/* smoothed round trip time << 3	*/
	u32	mdev;		/* medium deviation			*/
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	u32	rttvar;		/* smoothed mdev_max			*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/

	u32	packets_out;	/* Packets which are "in flight"	*/
	u32	retrans_out;	/* Retransmitted packets out		*/

	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	ecn_flags;	/* ECN status bits.			*/
	u8	reordering;	/* Packet reordering metric.		*/
	u32	snd_up;		/* Urgent pointer		*/

	u8	keepalive_probes; /* num of allowed keep alive probes	*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt;

/*慢启动拥塞控制
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold	慢启动阈值 若拥塞窗口小于此值 我们进入慢启动阶段 tcp_slow_start*/
 	u32	snd_cwnd;	   /* Sending congestion window     拥塞窗口的大小		*/
	u32	snd_cwnd_cnt;	/* Linear increase counter 超过慢启动阈值后 线性增长的个数	*/
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this 这是拥塞窗口可以增加到的最大数值*/
	u32	snd_cwnd_used;
	u32	snd_cwnd_stamp; //拥塞窗口最近一次生效的时间戳

 	u32	rcv_wnd;	/* Current receiver window		当前接收窗口的大小*/
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	lost_out;	/* Lost packets			*/
	u32	sacked_out;	/* SACK'd packets			*/
	u32	fackets_out;	/* FACK'd packets			*/
	u32	tso_deferred;
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;
	struct sk_buff *scoreboard_skb_hint;
	struct sk_buff *retransmit_skb_hint;

                                             //报文乱序的队列  将收到的乱序的报文暂时存储在此队列中 
	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

	/* SACKs data, these 2 need to be together (see tcp_build_and_update_options) */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block recv_sack_cache[4];

	struct sk_buff *highest_sack;   /* highest skb with SACK received
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */

	int     lost_cnt_hint;
	u32     retransmit_high;	/* L-bits may be on up to this seqno */

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */

	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* tracking retrans started here. */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	total_retrans;	/* Total retransmits for entire connection */

	u32	urg_seq;	/* Seq of received urgent pointer */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */

	int			linger2;

/* Receiver side RTT estimation */
	struct {
		u32	rtt;
		u32	seq;
		u32	time;
	} rcv_rtt_est;

/* Receiver queue space */
	struct {
		int	space;//表示当前接收缓存的大小（只包括应用层数据，单位为字节）。
		u32	seq;
		u32	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TCP_MD5SIG_MAXKEYLEN];
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
