#ifndef _NF_CONNTRACK_COMMON_H
#define _NF_CONNTRACK_COMMON_H
/* Connection state tracking for netfilter.  This is separated from,
   but required by, the NAT layer; it can also be used by an iptables
   extension. */
  //struct nf_conn 连接跟踪结构体
  //连接跟踪对该连接上的每个数据包表现为以下几种状态之一
enum ip_conntrack_info
{
	/*表示这个数据包对应的连接在两个方向都有数据包通过，
	并且这是ORIGINAL初始方向数据包（无论是TCP、UDP、ICMP数据包，
	只要在该连接的两个方向上已有数据包通过，就会将该连接设置为IP_CT_ESTABLISHED状态。
	不会根据协议中的标志位进行判断，例如TCP的SYN等）。
	但它表示不了这是第几个数据包，也说明不了这个CT是否是子连接。*/
	/* Part of an established connection (either direction). */
	IP_CT_ESTABLISHED,//Packet是一个已建连接的一部分，在其初始方向
	
	 /* 表示这个数据包对应的连接还没有REPLY方向数据包，当前数据包是ORIGINAL方向数据包。
	 并且这个连接关联一个已有的连接，是该已有连接的子连接，
	 （即status标志中已经设置了IPS_EXPECTED标志，该标志在init_conntrack()函数中设置）。
	 但无法判断是第几个数据包（不一定是第一个）*/
	/* Like NEW, but related to an existing connection, or ICMP error
	   (in either direction). */
	IP_CT_RELATED,//Packet属于一个已建连接的相关连接，在其初始方向

	 /* 表示这个数据包对应的连接还没有REPLY方向数据包，当前数据包是ORIGINAL方向数据包，
	 该连接不是子连接。但无法判断是第几个数据包（不一定是第一个）*/
	/* Started a new connection to track (only
           IP_CT_DIR_ORIGINAL); may be a retransmission. */
	IP_CT_NEW,//Packet试图建立新的连接


	 /* 这个状态一般不单独使用，通常以下面两种方式使用 
		IP_CT_ESTABLISHED + IP_CT_IS_REPLY  表示这个数据包对应的连接在两个方向都有数据包通过，
											并且这是REPLY应答方向数据包。但它表示不了这是第几个数据包，
											也说明不了这个CT是否是子连接
		IP_CT_RELATED + IP_CT_IS_REPLY	 这个状态仅在nf_conntrack_attach()函数中设置，
										用于本机返回REJECT，例如返回一个ICMP目的不可达报文， 
										或返回一个reset报文。它表示不了这是第几个数据包

	*/
	/* >= this indicates reply direction */
	IP_CT_IS_REPLY,//Packet是一个已建连接的一部分，在其响应方向

	/* Number of distinct IP_CT types (no NEW in reply dirn). */
	IP_CT_NUMBER = IP_CT_IS_REPLY * 2 - 1
};

/* Bitset representing status of connection. */
enum ip_conntrack_status {
	/* It's an expected connection: bit 0 set.  This bit never changed */
	IPS_EXPECTED_BIT = 0,///* 表示该连接是个子连接 */
	IPS_EXPECTED = (1 << IPS_EXPECTED_BIT),

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	IPS_SEEN_REPLY_BIT = 1, /* 表示该连接上双方向上都有数据包了 */
	IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),

	/* Conntrack should never be early-expired. */
	IPS_ASSURED_BIT = 2,/* TCP：在三次握手建立完连接后即设定该标志。UDP：如果在该连接上的两个方向都有数据包通过，
                            则再有数据包在该连接上通过时，就设定该标志。ICMP：不设置该标志 */
	IPS_ASSURED = (1 << IPS_ASSURED_BIT),

	/* Connection is confirmed: originating packet has left box */
	IPS_CONFIRMED_BIT = 3, /* 表示该连接已被添加到net->ct.hash表中 */
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),

	/* Connection needs src nat in orig dir.  This bit never changed. */
	IPS_SRC_NAT_BIT = 4,  /*在POSTROUTING处，当替换reply tuple完成时, 设置该标记 */
	IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),

	/* Connection needs dst nat in orig dir.  This bit never changed. */
	IPS_DST_NAT_BIT = 5,  /* 在PREROUTING处，当替换reply tuple完成时, 设置该标记 */
	IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),

	/* Both together. */
	IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),

	/* Connection needs TCP sequence adjusted. */
	IPS_SEQ_ADJUST_BIT = 6,
	IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),

	/* NAT initialization bits. */
	IPS_SRC_NAT_DONE_BIT = 7, /* 在POSTROUTING处，已被SNAT处理，并被加入到bysource链中，设置该标记 */
	IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT),

	IPS_DST_NAT_DONE_BIT = 8,/* 在PREROUTING处，已被DNAT处理，并被加入到bysource链中，设置该标记 */
	IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT),

	/* Both together */
	IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE),

	/* Connection is dying (removed from lists), can not be unset. */
	IPS_DYING_BIT = 9,   /* 表示该连接正在被释放，内核通过该标志保证正在被释放的ct不会被其它地方再次引用。
						有了这个标志，当某个连接要被删除时，即使它还在net->ct.hash中，也不会再次被引用。*/
	IPS_DYING = (1 << IPS_DYING_BIT),

	/* Connection has fixed timeout. */
	IPS_FIXED_TIMEOUT_BIT = 10,/* 固定连接超时时间，这将不根据状态修改连接超时时间。
								通过函数nf_ct_refresh_acct()修改超时时间时检查该标志。 */
	IPS_FIXED_TIMEOUT = (1 << IPS_FIXED_TIMEOUT_BIT),
};

#ifdef __KERNEL__
struct ip_conntrack_stat
{
	unsigned int searched;
	unsigned int found;
	unsigned int new;
	unsigned int invalid;
	unsigned int ignore;
	unsigned int delete;
	unsigned int delete_list;
	unsigned int insert;
	unsigned int insert_failed;
	unsigned int drop;
	unsigned int early_drop;
	unsigned int error;
	unsigned int expect_new;
	unsigned int expect_create;
	unsigned int expect_delete;
};

/* call to create an explicit dependency on nf_conntrack. */
extern void need_conntrack(void);

#endif /* __KERNEL__ */

#endif /* _NF_CONNTRACK_COMMON_H */
