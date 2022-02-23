/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Interfaces handler.
 *
 * Version:	@(#)dev.h	1.0.10	08/12/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Donald J. Becker, <becker@cesdis.gsfc.nasa.gov>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Bjorn Ekwall. <bj0rn@blox.se>
 *              Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *		Moved to /usr/include/linux for NET3
 */
#ifndef _LINUX_NETDEVICE_H
#define _LINUX_NETDEVICE_H

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#ifdef __KERNEL__
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <asm/atomic.h>
#include <asm/cache.h>
#include <asm/byteorder.h>

#include <linux/device.h>
#include <linux/percpu.h>
#include <linux/rculist.h>
#include <linux/dmaengine.h>
#include <linux/workqueue.h>

#include <linux/ethtool.h>
#include <net/net_namespace.h>
#include <net/dsa.h>
#ifdef CONFIG_DCB
#include <net/dcbnl.h>
#endif

struct vlan_group;
struct netpoll_info;
/* 802.11 specific */
struct wireless_dev;
					/* source back-compat hooks */
#define SET_ETHTOOL_OPS(netdev,ops) \
	( (netdev)->ethtool_ops = (ops) )

#define HAVE_ALLOC_NETDEV		/* feature macro: alloc_xxxdev
					   functions are available. */
#define HAVE_FREE_NETDEV		/* free_netdev() */
#define HAVE_NETDEV_PRIV		/* netdev_priv() */

#define NET_XMIT_SUCCESS	0
#define NET_XMIT_DROP		1	/* skb dropped			*/
#define NET_XMIT_CN		2	/* congestion notification	*/
#define NET_XMIT_POLICED	3	/* skb is shot by police	*/
#define NET_XMIT_MASK		0xFFFF	/* qdisc flags in net/sch_generic.h */

/* Backlog congestion levels */
#define NET_RX_SUCCESS		0   /* keep 'em coming, baby */
#define NET_RX_DROP		1  /* packet dropped */

/* NET_XMIT_CN is special. It does not guarantee that this packet is lost. It
 * indicates that the device will soon be dropping packets, or already drops
 * some packets of the same priority; prompting us to send less aggressively. */
#define net_xmit_eval(e)	((e) == NET_XMIT_CN? 0 : (e))
#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)

/* Driver transmit return codes */
enum netdev_tx {
	NETDEV_TX_OK = 0,	/* driver took care of packet  传输成功*/
	NETDEV_TX_BUSY,		/* driver tx path was busy NIC传输缓冲池内没有内存*/
	NETDEV_TX_LOCKED = -1,	/* driver tx lock was already taken 驱动程序被锁住了*/
};
typedef enum netdev_tx netdev_tx_t;

#endif

//硬件地址的最大长度
#define MAX_ADDR_LEN	32		/* Largest hardware address length */

#ifdef  __KERNEL__
/*
 *	Compute the worst case header length according to the protocols
 *	used.
 */

#if defined(CONFIG_WLAN_80211) || defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
# if defined(CONFIG_MAC80211_MESH)
#  define LL_MAX_HEADER 128
# else
#  define LL_MAX_HEADER 96
# endif
#elif defined(CONFIG_TR) || defined(CONFIG_TR_MODULE)
# define LL_MAX_HEADER 48
#else
# define LL_MAX_HEADER 32
#endif

#if !defined(CONFIG_NET_IPIP) && !defined(CONFIG_NET_IPIP_MODULE) && \
    !defined(CONFIG_NET_IPGRE) &&  !defined(CONFIG_NET_IPGRE_MODULE) && \
    !defined(CONFIG_IPV6_SIT) && !defined(CONFIG_IPV6_SIT_MODULE) && \
    !defined(CONFIG_IPV6_TUNNEL) && !defined(CONFIG_IPV6_TUNNEL_MODULE)
#define MAX_HEADER LL_MAX_HEADER //最大链路层首部长度
#else
#define MAX_HEADER (LL_MAX_HEADER + 48)
#endif

#endif  /*  __KERNEL__  */

/*
 *	Network device statistics. Akin to the 2.0 ether stats but
 *	with byte counters.
 */
//所有网络设备共有的的统计数据 get_stats()
struct net_device_stats
{
	unsigned long	rx_packets;		/* total packets received	收到的数据包数*/
	unsigned long	tx_packets;		/* total packets transmitted	发送的数据包数*/
	unsigned long	rx_bytes;		/* total bytes received 	收到的字节数,可以通过sk_buff结构体的成员len来获取*/
	unsigned long	tx_bytes;		/* total bytes transmitted	发送的字节数,可以通过sk_buff结构体的成员len来获取*/
	unsigned long	rx_errors;		/* bad packets received		收到的错误数据包数*/
	unsigned long	tx_errors;		/* packet transmit problems	发送的错误数据包数*/
	unsigned long	rx_dropped;		/* no space in linux buffers	*/
	unsigned long	tx_dropped;		/* no space available in linux	*/
	unsigned long	multicast;		/* multicast packets received	*/
	unsigned long	collisions;

	/* detailed rx_errors: */
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;		/* receiver ring buff overflow	*/
	unsigned long	rx_crc_errors;		/* recved pkt with crc error	*/
	unsigned long	rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long	rx_fifo_errors;		/* recv'r fifo overrun		*/
	unsigned long	rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	
	/* for cslip etc */
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};


/* Media selection options. */
enum {
        IF_PORT_UNKNOWN = 0,
        IF_PORT_10BASE2,
        IF_PORT_10BASET,
        IF_PORT_AUI,
        IF_PORT_100BASET,
        IF_PORT_100BASETX,
        IF_PORT_100BASEFX
};

#ifdef __KERNEL__

#include <linux/cache.h>
#include <linux/skbuff.h>

struct neighbour;
struct neigh_parms;
struct sk_buff;

struct netif_rx_stats
{
	unsigned total; //已处理的入口帧总数，包括被丢弃的 netif_rx netif_receive_skb
	unsigned dropped;//帧被丢弃的数目
	unsigned time_squeeze;//net_tx_action()由于 处理包个数以及处理的时间的限制而返回的次数
	unsigned cpu_collision;//cpu无法获得驱动程序锁的次数,因为该锁被另一个cpu使用 handle_dev_cpu_collision()
};

struct netif_rx_stats netdev_rx_stat; //自己定义
DECLARE_PER_CPU(struct netif_rx_stats, netdev_rx_stat);

struct dev_addr_list
{
	struct dev_addr_list	*next;
	u8			da_addr[MAX_ADDR_LEN]; //用于构成一个多播地址链表
	u8			da_addrlen;
	u8			da_synced;
	int			da_users;
	int			da_gusers;
};

/*
 *	We tag multicasts with these structures.
 */

//用于链路层多波地址
#define dev_mc_list	dev_addr_list
#define dmi_addr	da_addr //具体多播地址
#define dmi_addrlen	da_addrlen//多播地址长度，一般是硬件地址长度
#define dmi_users	da_users //该多播地址结构的使用数
#define dmi_gusers	da_gusers

struct netdev_hw_addr {
	struct list_head	list;
	unsigned char		addr[MAX_ADDR_LEN];
	unsigned char		type;
#define NETDEV_HW_ADDR_T_LAN		1
#define NETDEV_HW_ADDR_T_SAN		2
#define NETDEV_HW_ADDR_T_SLAVE		3
#define NETDEV_HW_ADDR_T_UNICAST	4
	int			refcount;
	bool			synced;
	struct rcu_head		rcu_head;
};

struct netdev_hw_addr_list {
	struct list_head	list;
	int			count;
};

struct hh_cache
{
	struct hh_cache *hh_next;	/* Next entry			     */
	atomic_t	hh_refcnt;	/* number of users                   */
/*
 * We want hh_output, hh_len, hh_lock and hh_data be a in a separate
 * cache line on SMP.
 * They are mostly read, but hh_refcnt may be changed quite frequently,
 * incurring cache line ping pongs.
 */
	__be16		hh_type ____cacheline_aligned_in_smp;
					/* protocol identifier, f.e ETH_P_IP
                                         *  NOTE:  For VLANs, this will be the
                                         *  encapuslated type. --BLG
                                         */
	u16		hh_len;		/* length of header */
	int		(*hh_output)(struct sk_buff *skb);
	seqlock_t	hh_lock;

	/* cached hardware header; allow for machine alignment needs.        */
#define HH_DATA_MOD	16
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - (((__len - 1) & (HH_DATA_MOD - 1)) + 1))
#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
	unsigned long	hh_data[HH_DATA_ALIGN(LL_MAX_HEADER) / sizeof(long)];
};

/* Reserve HH_DATA_MOD byte aligned hard_header_len, but at least that much.
 * Alternative is:
 *   dev->hard_header_len ? (dev->hard_header_len +
 *                           (HH_DATA_MOD - 1)) & ~(HH_DATA_MOD - 1) : 0
 *
 * We could use other alignment values, but we must maintain the
 * relationship HH alignment <= LL alignment.
 *
 * LL_ALLOCATED_SPACE also takes into account the tailroom the device
 * may need.
 */
#define LL_RESERVED_SPACE(dev) \
	((((dev)->hard_header_len+(dev)->needed_headroom)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+(dev)->needed_headroom+(extra))&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_ALLOCATED_SPACE(dev) \
	((((dev)->hard_header_len+(dev)->needed_headroom+(dev)->needed_tailroom)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)

struct header_ops {
	int	(*create) (struct sk_buff *skb, struct net_device *dev,
			   unsigned short type, const void *daddr,
			   const void *saddr, unsigned len);
	int	(*parse)(const struct sk_buff *skb, unsigned char *haddr);
	int	(*rebuild)(struct sk_buff *skb);
#define HAVE_HEADER_CACHE
	int	(*cache)(const struct neighbour *neigh, struct hh_cache *hh);
	void	(*cache_update)(struct hh_cache *hh,
				const struct net_device *dev,
				const unsigned char *haddr);
};

/* These flag bits are private to the generic network queueing
 * layer, they may not be explicitly referenced by any other
 * code.
 */
enum netdev_state_t
{
	__LINK_STATE_START,//设备开启      netif_running()检查
	__LINK_STATE_PRESENT,//设备存在    netif_device_present()检查
	__LINK_STATE_NOCARRIER,//没有载波  没有网线插入
	__LINK_STATE_LINKWATCH_PENDING,   //链路监测 有未处理的链路变更事件
	__LINK_STATE_DORMANT,
};

/*
 * This structure holds at boot time configured netdevice settings. They
 * are then used in the device probing.
 */
struct netdev_boot_setup {
	char name[IFNAMSIZ];//设备名称
	struct ifmap map;
};
#define NETDEV_BOOT_SETUP_MAX 8//引导期间配置设备的最大数目

extern int __init netdev_boot_setup(char *str);

/*
 * Structure for NAPI scheduling similar to tasklet but with weighting
 */
 //驱动程序实现一个 下面结构的对象 并放入自己私有数据结构中
 //驱动调用netif_napi_add()对它进行初始化
struct napi_struct {
	/* The poll_list must only be managed by the entity which
	 * changes the state of the NAPI_STATE_SCHED bit.  This means
	 * whoever atomically sets that bit can add this napi_struct
	 * to the per-cpu poll_list, and whoever clears that bit
	 * can remove from the list right before clearing the bit.
	 */
	struct list_head	poll_list;//将当前设备放入内核维护的一个轮询列表中,此链表中的设备都处于中断功能关闭 内核当前正要轮询 

	unsigned long		state;
	int			weight; //当前设备的权重
	int			(*poll)(struct napi_struct *, int);//驱动实现 将在内核对当前设备轮询时被调用
#ifdef CONFIG_NETPOLL
	spinlock_t		poll_lock;
	int			poll_owner;
#endif

	unsigned int		gro_count;

	struct net_device	*dev;
	struct list_head	dev_list;
	struct sk_buff		*gro_list;
	struct sk_buff		*skb;
};

enum
{
	NAPI_STATE_SCHED,	/* Poll is scheduled */
	NAPI_STATE_DISABLE,	/* Disable pending */
	NAPI_STATE_NPSVC,	/* Netpoll - don't dequeue from poll_list */
};

enum {
	GRO_MERGED,
	GRO_MERGED_FREE,
	GRO_HELD,
	GRO_NORMAL,
	GRO_DROP,
};

extern void __napi_schedule(struct napi_struct *n);

static inline int napi_disable_pending(struct napi_struct *n)
{
	return test_bit(NAPI_STATE_DISABLE, &n->state);
}

/**
 *	napi_schedule_prep - check if napi can be scheduled
 *	@n: napi context
 *
 * Test if NAPI routine is already running, and if not mark
 * it as running.  This is used as a condition variable
 * insure only one NAPI poll instance runs.  We also make
 * sure there is no pending NAPI disable.
 */
static inline int napi_schedule_prep(struct napi_struct *n)
{
	return !napi_disable_pending(n) &&
		   !test_and_set_bit(NAPI_STATE_SCHED, &n->state);
}

/**
 *	napi_schedule - schedule NAPI poll
 *	@n: napi context
 *
 * Schedule NAPI poll routine to be called if it is not already
 * running.
 */
static inline void napi_schedule(struct napi_struct *n)
{
	if (napi_schedule_prep(n))
		__napi_schedule(n);
}

/* Try to reschedule poll. Called by dev->poll() after napi_complete().  */
static inline int napi_reschedule(struct napi_struct *napi)
{
	if (napi_schedule_prep(napi)) {
		__napi_schedule(napi);
		return 1;
	}
	return 0;
}

/**
 *	napi_complete - NAPI processing complete
 *	@n: napi context
 *
 * Mark NAPI processing as complete.
 */
extern void __napi_complete(struct napi_struct *n);
extern void napi_complete(struct napi_struct *n);

/**
 *	napi_disable - prevent NAPI from scheduling
 *	@n: napi context
 *
 * Stop NAPI from being scheduled on this context.
 * Waits till any outstanding processing completes.
 */
static inline void napi_disable(struct napi_struct *n)
{
	set_bit(NAPI_STATE_DISABLE, &n->state);
	while (test_and_set_bit(NAPI_STATE_SCHED, &n->state))
		msleep(1);
	clear_bit(NAPI_STATE_DISABLE, &n->state);
}

/**
 *	napi_enable - enable NAPI scheduling
 *	@n: napi context
 *
 * Resume NAPI from being scheduled on this context.
 * Must be paired with napi_disable.
 */
static inline void napi_enable(struct napi_struct *n)
{
	BUG_ON(!test_bit(NAPI_STATE_SCHED, &n->state));
	smp_mb__before_clear_bit();
	clear_bit(NAPI_STATE_SCHED, &n->state);
}

#ifdef CONFIG_SMP
/**
 *	napi_synchronize - wait until NAPI is not running
 *	@n: napi context
 *
 * Wait until NAPI is done being scheduled on this context.
 * Waits till any outstanding processing completes but
 * does not disable future activations.
 */
static inline void napi_synchronize(const struct napi_struct *n)
{
	while (test_bit(NAPI_STATE_SCHED, &n->state))
		msleep(1);
}
#else
# define napi_synchronize(n)	barrier()
#endif

enum netdev_queue_state_t
{
	__QUEUE_STATE_XOFF,
	__QUEUE_STATE_FROZEN,
};

struct netdev_queue {
/*
 * read mostly part
 */
	struct net_device	*dev;
	struct Qdisc		*qdisc;
	unsigned long		state;
	struct Qdisc		*qdisc_sleeping;
/*
 * write mostly part
 */
	spinlock_t		_xmit_lock ____cacheline_aligned_in_smp;
	int			xmit_lock_owner;
	/*
	 * please use this field instead of dev->trans_start
	 */
	unsigned long		trans_start;
	unsigned long		tx_bytes;
	unsigned long		tx_packets;
	unsigned long		tx_dropped;
} ____cacheline_aligned_in_smp;


/*
 * This structure defines the management hooks for network devices.
 * The following hooks can be defined; unless noted otherwise, they are
 * optional and can be filled with a null pointer.
 *
 * int (*ndo_init)(struct net_device *dev);
 *     This function is called once when network device is registered.
 *     The network device can use this to any late stage initializaton
 *     or semantic validattion. It can fail with an error code which will
 *     be propogated back to register_netdev
 *
 * void (*ndo_uninit)(struct net_device *dev);
 *     This function is called when device is unregistered or when registration
 *     fails. It is not called if init fails.
 *
 * int (*ndo_open)(struct net_device *dev);
 *     This function is called when network device transistions to the up
 *     state.
 *
 * int (*ndo_stop)(struct net_device *dev);
 *     This function is called when network device transistions to the down
 *     state.
 *
 * netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb,
 *                               struct net_device *dev);
 *	Called when a packet needs to be transmitted.
 *	Must return NETDEV_TX_OK , NETDEV_TX_BUSY.
 *        (can also return NETDEV_TX_LOCKED iff NETIF_F_LLTX)
 *	Required can not be NULL.
 *
 * u16 (*ndo_select_queue)(struct net_device *dev, struct sk_buff *skb);
 *	Called to decide which queue to when device supports multiple
 *	transmit queues.
 *
 * void (*ndo_change_rx_flags)(struct net_device *dev, int flags);
 *	This function is called to allow device receiver to make
 *	changes to configuration when multicast or promiscious is enabled.
 *
 * void (*ndo_set_rx_mode)(struct net_device *dev);
 *	This function is called device changes address list filtering.
 *
 * void (*ndo_set_multicast_list)(struct net_device *dev);
 *	This function is called when the multicast address list changes.
 *
 * int (*ndo_set_mac_address)(struct net_device *dev, void *addr);
 *	This function  is called when the Media Access Control address
 *	needs to be changed. If this interface is not defined, the
 *	mac address can not be changed.
 *
 * int (*ndo_validate_addr)(struct net_device *dev);
 *	Test if Media Access Control address is valid for the device.
 *
 * int (*ndo_do_ioctl)(struct net_device *dev, struct ifreq *ifr, int cmd);
 *	Called when a user request an ioctl which can't be handled by
 *	the generic interface code. If not defined ioctl's return
 *	not supported error code.
 *
 * int (*ndo_set_config)(struct net_device *dev, struct ifmap *map);
 *	Used to set network devices bus interface parameters. This interface
 *	is retained for legacy reason, new devices should use the bus
 *	interface (PCI) for low level management.
 *
 * int (*ndo_change_mtu)(struct net_device *dev, int new_mtu);
 *	Called when a user wants to change the Maximum Transfer Unit
 *	of a device. If not defined, any request to change MTU will
 *	will return an error.
 *
 * void (*ndo_tx_timeout)(struct net_device *dev);
 *	Callback uses when the transmitter has not made any progress
 *	for dev->watchdog ticks.
 *
 * struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);
 *	Called when a user wants to get the network device usage
 *	statistics. If not defined, the counters in dev->stats will
 *	be used.
 *
 * void (*ndo_vlan_rx_register)(struct net_device *dev, struct vlan_group *grp);
 *	If device support VLAN receive accleration
 *	(ie. dev->features & NETIF_F_HW_VLAN_RX), then this function is called
 *	when vlan groups for the device changes.  Note: grp is NULL
 *	if no vlan's groups are being used.
 *
 * void (*ndo_vlan_rx_add_vid)(struct net_device *dev, unsigned short vid);
 *	If device support VLAN filtering (dev->features & NETIF_F_HW_VLAN_FILTER)
 *	this function is called when a VLAN id is registered.
 *
 * void (*ndo_vlan_rx_kill_vid)(struct net_device *dev, unsigned short vid);
 *	If device support VLAN filtering (dev->features & NETIF_F_HW_VLAN_FILTER)
 *	this function is called when a VLAN id is unregistered.
 *
 * void (*ndo_poll_controller)(struct net_device *dev);
 */
#define HAVE_NET_DEVICE_OPS
//e1000_netdev_ops
struct net_device_ops 
{
    //在对网络设备做一些晚期的初始化
	int			(*ndo_init)(struct net_device *dev);
	//为nod_init的逆过程
	void			(*ndo_uninit)(struct net_device *dev);

	//在网络设备被激活 接口被打开此函数将得到执行的机会 比如使用ifconfig激活设备
	int			(*ndo_open)(struct net_device *dev);

	//在网络设备接口被关闭时有机会执行
	int			(*ndo_stop)(struct net_device *dev);

	//实现数据包的发送 当网络子系统中有数据要发送时,就会执行此函数
	netdev_tx_t		(*ndo_start_xmit) (struct sk_buff *skb,
						               struct net_device *dev);
	
	u16			(*ndo_select_queue)(struct net_device *dev,
						    struct sk_buff *skb);
#define HAVE_CHANGE_RX_FLAGS
	void			(*ndo_change_rx_flags)(struct net_device *dev,
						       int flags);
#define HAVE_SET_RX_MODE
	void			(*ndo_set_rx_mode)(struct net_device *dev);
#define HAVE_MULTICAST
	void			(*ndo_set_multicast_list)(struct net_device *dev);
#define HAVE_SET_MAC_ADDR
	int			(*ndo_set_mac_address)(struct net_device *dev,
						       void *addr);
#define HAVE_VALIDATE_ADDR
	int			(*ndo_validate_addr)(struct net_device *dev);
#define HAVE_PRIVATE_IOCTL
	int			(*ndo_do_ioctl)(struct net_device *dev,
					        struct ifreq *ifr, int cmd);
#define HAVE_SET_CONFIG
	int			(*ndo_set_config)(struct net_device *dev,
					          struct ifmap *map);
#define HAVE_CHANGE_MTU
	int			(*ndo_change_mtu)(struct net_device *dev,
						  int new_mtu);
	int			(*ndo_neigh_setup)(struct net_device *dev,
						   struct neigh_parms *);
#define HAVE_TX_TIMEOUT
	void			(*ndo_tx_timeout) (struct net_device *dev);

	struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);

	void			(*ndo_vlan_rx_register)(struct net_device *dev,
						        struct vlan_group *grp);
	void			(*ndo_vlan_rx_add_vid)(struct net_device *dev,
						       unsigned short vid);
	void			(*ndo_vlan_rx_kill_vid)(struct net_device *dev,
						        unsigned short vid);
#ifdef CONFIG_NET_POLL_CONTROLLER
#define HAVE_NETDEV_POLL
	void                    (*ndo_poll_controller)(struct net_device *dev);
#endif
#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
	int			(*ndo_fcoe_enable)(struct net_device *dev);
	int			(*ndo_fcoe_disable)(struct net_device *dev);
	int			(*ndo_fcoe_ddp_setup)(struct net_device *dev,
						      u16 xid,
						      struct scatterlist *sgl,
						      unsigned int sgc);
	int			(*ndo_fcoe_ddp_done)(struct net_device *dev,
						     u16 xid);
#endif
};

/*
 *	The DEVICE structure.
 *	Actually, this whole structure is a big mistake.  It mixes I/O
 *	data with strictly "high-level" data, and it has to know about
 *	almost every data structure used in the INET module.
 *
 *	FIXME: cleanup struct net_device such that network protocol info
 *	moves out.
 */
//网络栈核心数据结构
//网络抽象层保存设备的地址编号
struct net_device
{

	char			name[IFNAMSIZ]; //网卡设备名称,比如eth0，eth1，eth2
	                                //ethX  以太网设备
	                                //pppX  调制解调器等ppp连接类型的设备
	                                //isdnX ISDN卡
	                                //lo  环回设备
	                                
	struct hlist_node	name_hlist;//以名字为索引的哈希表
	char 			*ifalias; //snmp的别名

	unsigned long		mem_end;	/* shared mem end	//该设备的内存结束地址*/
	unsigned long		mem_start;	/* shared mem start	//该设备的内存起始地址*/
	unsigned long		base_addr;	/* device I/O address	//该设备自有的内存映射到IO内存的起始地址*/
	unsigned int		irq;		/* device IRQ number	 //该设备的中断号*/

	/*
	 *	Some hardware also needs these fields, but they are not
	 *	part of the usual set specified in Space.c.
	 */

	unsigned char		if_port;	/* Selectable AUI, TP,..//多端口设备使用的端口类型*/
	unsigned char		dma;		/* DMA channel		//该设备的DMA通道  request_dma()获取dma通道 */

	unsigned long		state;  //网络设备和网络适配器的状态信息 __LINK_STATE_START 
	                            //可设置一些标志 定义设备队列规则状态

	struct list_head	dev_list;//将当前设备加入到所属命名空间中的dev_base_head所管理的全局链表
	
	struct list_head	napi_list;//用于支持NAPI特性的网络设备 它将napi_struct{}中的dev_list 加到napi_list对应的链上

	/* Net device features */
	unsigned long		features;//用来标识接口的各种能力和特性
#define NETIF_F_SG		1	/* Scatter/gather IO. */
#define NETIF_F_IP_CSUM		2	/* 此设备可以在硬件中计算L4校验和.但是只针对ipv4的tcp和udp */
#define NETIF_F_NO_CSUM		4	/* 此设备很可靠 不需要做checksum 比如koopback*/
#define NETIF_F_HW_CSUM		8	/* 此设备可以为任何协议在硬件中计算l4校验和*/
#define NETIF_F_IPV6_CSUM	16	/* Can checksum TCP/UDP over IPV6 */
#define NETIF_F_HIGHDMA		32	/* Can DMA to high memory. */
#define NETIF_F_FRAGLIST	64	/* Scatter/gather IO. */
#define NETIF_F_HW_VLAN_TX	128	/* Transmit VLAN hw acceleration 通过硬件发送vlan报文 这样可以加速发送*/
#define NETIF_F_HW_VLAN_RX	256	/* Receive VLAN hw acceleration 通过硬件接收valn报文,加速接收*/
#define NETIF_F_HW_VLAN_FILTER	512	/* Receive filtering on VLAN */
#define NETIF_F_VLAN_CHALLENGED	1024	/* Device cannot handle VLAN packetss设备部支持vlan报文 报文可能被认为错包而丢弃 */
#define NETIF_F_GSO		2048	/* Enable software GSO. */
#define NETIF_F_LLTX		4096	/* LockLess TX - deprecated. Please */
					/* do not use LLTX in new drivers */
#define NETIF_F_NETNS_LOCAL	8192	/* Does not change network namespaces */
#define NETIF_F_GRO		16384	/* Generic receive offload */
#define NETIF_F_LRO		32768	/* large receive offload */

/* the GSO_MASK reserves bits 16 through 23 */
#define NETIF_F_FCOE_CRC	(1 << 24) /* FCoE CRC32 */
#define NETIF_F_SCTP_CSUM	(1 << 25) /* SCTP checksum offload */
#define NETIF_F_FCOE_MTU	(1 << 26) /* Supports max FCoE MTU, 2158 bytes*/

	/* Segmentation offload features */
#define NETIF_F_GSO_SHIFT	16
#define NETIF_F_GSO_MASK	0x00ff0000
#define NETIF_F_TSO		(SKB_GSO_TCPV4 << NETIF_F_GSO_SHIFT)
#define NETIF_F_UFO		(SKB_GSO_UDP << NETIF_F_GSO_SHIFT)
#define NETIF_F_GSO_ROBUST	(SKB_GSO_DODGY << NETIF_F_GSO_SHIFT)
#define NETIF_F_TSO_ECN		(SKB_GSO_TCP_ECN << NETIF_F_GSO_SHIFT)
#define NETIF_F_TSO6		(SKB_GSO_TCPV6 << NETIF_F_GSO_SHIFT)
#define NETIF_F_FSO		(SKB_GSO_FCOE << NETIF_F_GSO_SHIFT)

	/* List of features with software fallbacks. */
#define NETIF_F_GSO_SOFTWARE	(NETIF_F_TSO | NETIF_F_TSO_ECN | NETIF_F_TSO6)


#define NETIF_F_GEN_CSUM	(NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)
#define NETIF_F_V4_CSUM		(NETIF_F_GEN_CSUM | NETIF_F_IP_CSUM)
#define NETIF_F_V6_CSUM		(NETIF_F_GEN_CSUM | NETIF_F_IPV6_CSUM)
#define NETIF_F_ALL_CSUM	(NETIF_F_V4_CSUM | NETIF_F_V6_CSUM)

	/*
	 * If one device supports one of these features, then enable them
	 * for all in netdev_increment_features.
	 */
#define NETIF_F_ONE_FOR_ALL	(NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ROBUST | \
				 NETIF_F_SG | NETIF_F_HIGHDMA |		\
				 NETIF_F_FRAGLIST)

	/* Interface index. Unique device identifier	*/
	int			ifindex;//内核指定的索引号，比如第一个，第二个设备等等 dev_new_index()
	int			iflink;//主要用于虚拟隧道设备 可用于标志抵达隧道另一端的真实设备

	struct net_device_stats	stats; //用来保存统计信息的net_device_stats结构体

#ifdef CONFIG_WIRELESS_EXT
	/* List of functions to handle Wireless Extensions (instead of ioctl).
	 * See <net/iw_handler.h> for details. Jean II */
	const struct iw_handler_def *	wireless_handlers;
	/* Instance data managed by the core of Wireless Extensions. */
	struct iw_public_data *	wireless_data;
#endif
	/* Management operations */
	const struct net_device_ops *netdev_ops;//网络设备方法操作集 网络设备回调函数  用于打开和停止设备 开始传输 修改网络设备MTU
	const struct ethtool_ops *ethtool_ops;//它支持通过命令行ethtool 来获得设备的信息 用于设置或取出不同设备参数的配置

	/* Hardware header description */
	const struct header_ops *header_ops;//针对网络层访问链路帧的操作集合
	                                    //对于以太网为eth_header_ops{eth_header,...}

	unsigned int		flags;	/* 用于存储不同的状态，它们绝大多数表示设备的性能，
	                              不过，其中的IFF_UP用于指示设备是激活的(UP)还是关闭的(DOWN),	*/
                               //IFF_BROADCAST IFF_UP  IFF_RUNNING

	unsigned short		gflags;
        unsigned short          priv_flags; /* 用于存储用户空间不可见的标志  此字段为vlan 和bridge虚拟设备使用*/
	unsigned short		padded;	/*通过alloc_netdev()后增加了多少为对齐而用的字节 */

	unsigned char		operstate; /* RFC2863 operstate */
	unsigned char		link_mode; /* mapping policy to operstate */

	unsigned		mtu;	/*最大传输单元,也叫最大数据包 对于以太网此值为1500	
                              PPP   296,        SLIP  296,        Ethernet 1500,     ISDN 1500
                              PLIP 1500,        Wavelan 1500,     EtherChannel 2024, FDDI 4352
                              Token Ring 4464,  Token Bus 8182,   Token Ring16M/s 17914     
                              Hyperchannel 65535  
	                          */
	
	unsigned short		type;	/*接口的硬件类型  ARPHRD_ETHER*/
	unsigned short		hard_header_len;	/* 硬件协议头的长度  对于以太网此处为14个字节*/

	/* extra head- and tailroom the hardware may need, but not in all cases
	 * can this be guaranteed, especially tailroom. Some cases also use
	 * LL_MAX_HEADER instead to allocate the skb.
	 */
	unsigned short		needed_headroom;
	unsigned short		needed_tailroom;

	struct net_device	*master; /* Pointer to master device of a group,
					  * which this device is member of.指向一个组的主设备
					  */

	/* Interface address info. */
	unsigned char		perm_addr[MAX_ADDR_LEN]; /* permanent hw address */
	unsigned char		addr_len;	/*硬件地址长度 对于以太网此处为6即MAC地址长度*/
	unsigned short          dev_id;		/* 用于区别由不同OS同时共享的同一种设备的诸多虚拟实例*/

	struct netdev_hw_addr_list	uc;	//unicast 单播MAC地址链表
	int			uc_promisc;
	spinlock_t		addr_list_lock;

	struct dev_addr_list	*mc_list;	/*接口监听的所有多播地址 dev_mc_add()*/
	int			mc_count;	         /* 多播地址数目	*/
	
	unsigned int		promiscuity;//多个客户端都会要求混杂模式, 进入混杂模式时 递增此计数器dev_set_promiscuity()
	                                 //为非零的时候flags 的IFF_PROMISC会置位
	unsigned int		allmulti;//非0 引起此设备监听所有的多播地址 此为一个引用计数 dev_set_allmulti()


	/* Protocol specific pointers */

	//以下是和协议特定的数据
#ifdef CONFIG_NET_DSA
	void			*dsa_ptr;	/* dsa specific data */
#endif
	void 			*atalk_ptr;	/* AppleTalk link 	*/
	void			*ip_ptr;	/* IPv4 specific data	in_device结构*/
	void                    *dn_ptr;        /* DECnet specific data */
	void                    *ip6_ptr;       /* IPv6 specific data */
	void			*ec_ptr;	/* Econet specific data	*/
	void			*ax25_ptr;	/* AX.25 specific data */
	struct wireless_dev	*ieee80211_ptr;	/* IEEE 802.11 specific data,
						   assign before registering */

/*
 * Cache line mostly used on receive path (including eth_type_trans())
 */
	unsigned long		last_rx;	/* Time of last Rx	//接收数据包的时间戳,调用netif_rx()后赋上jiffies即可*/
	/* Interface address info used in eth_type_trans() */
	unsigned char		*dev_addr;	//指向网络设备硬件地址的指针

	struct netdev_hw_addr_list	dev_addrs; //网络设备硬件地址链表

	
	unsigned char		broadcast[MAX_ADDR_LEN];//硬件广播地址

	struct netdev_queue	rx_queue;  //网络设备接收队列

	struct netdev_queue	*_tx ____cacheline_aligned_in_smp;//网络设备发送队列

	unsigned int		num_tx_queues;//由alloc_netdev_mq()函数分配的属于当前网络设备的发送队列的数量

	unsigned int		real_num_tx_queues;//当前活动的的发送队列的数量

	/* root qdisc from userspace point of view */
	struct Qdisc		*qdisc;

	unsigned long		tx_queue_len;	/*设备的传送队列的长度 */
	spinlock_t		    tx_global_lock;
/*
 * One part is mostly used on xmit path (device)
 */
	/* These may be needed for future network-power-down code. */

	/*
	 * trans_start here is expensive for high speed devices on SMP,
	 * please use netdev_queue->trans_start instead.
	 */
	unsigned long		trans_start;	/* 由驱动程序设置 记录上次帧传输启动的时间*/

	int			watchdog_timeo; /*dev_watchdog() 用于网络设备在传输数据包时传输超时的到期时间
                                  当超时 定义在net_device_ops{}中的ndo_txtimeout函数将被调用 如e1000_netdev_ops
                                  在__netdev_watchdog_up()中将watchdog_timer和watchdog_timeo进行联系
	                              */
	                                   //register_netdevice()->dev_init_scheduler()->dev_watchdog()
	struct timer_list	watchdog_timer;//由流量控制启动的定时器

	/* Number of references to this device */
	atomic_t		refcnt ____cacheline_aligned_in_smp;

	/* delayed register/unregister */
	struct list_head	todo_list;

	
	/* device index hash chain */
	struct hlist_node	index_hlist;

	struct net_device	*link_watch_next;//用于链路状态变更事件链表   linkwatch_add_event()

	enum { NETREG_UNINITIALIZED=0,  //定义为0 net_device已分配 且已经初始化
	       NETREG_REGISTERED,	/*设备注册完成 */
	       NETREG_UNREGISTERING,	/* called unregister_netdevice//net_device已由“net_device结构的组织”提及的结构内删除 */
	       NETREG_UNREGISTERED,	/*设备完全除名*/
	       NETREG_RELEASED,		/* called free_netdev  //所有对net_device结构的引用已释放*/
	       NETREG_DUMMY,		/* dummy device for NAPI poll */
	} reg_state;//当前设备在系统中的注册状态

	/* Called from unregister, can be used to call free_netdev */
	void (*destructor)(struct net_device *dev);

#ifdef CONFIG_NETPOLL
	struct netpoll_info	*npinfo;
#endif

#ifdef CONFIG_NET_NS
	struct net		*nd_net;//所在的命名空间
#endif

	/* mid-layer private */
	void			*ml_priv;

	/* bridge stuff */
	struct net_bridge_port	*br_port;//表示桥接端口所需要的额外信息 当端口没有开启桥接功能此处为NULL
	/* macvlan */
	struct macvlan_port	*macvlan_port;
	/* GARP */
	struct garp_port	*garp_port;

	struct device		dev;//会将网络设备加入到设备驱动模型的体系中


	/* space for optional statistics and wireless sysfs groups */
	const struct attribute_group *sysfs_groups[3];

	/* rtnetlink link ops */
	const struct rtnl_link_ops *rtnl_link_ops;

	/* VLAN feature mask */
	unsigned long  vlan_features;

	/* for setting kernel sock attribute on TCP connection setup */
#define GSO_MAX_SIZE		65536
	unsigned int		gso_max_size;

#ifdef CONFIG_DCB
	/* Data Center Bridging netlink ops */
	struct dcbnl_rtnl_ops *dcbnl_ops;
#endif

#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
	/* max exchange id for FCoE LRO by ddp */
	unsigned int		fcoe_ddp_xid;
#endif
};
#define to_net_dev(d) container_of(d, struct net_device, dev)

#define	NETDEV_ALIGN		32

static inline
struct netdev_queue *netdev_get_tx_queue(const struct net_device *dev,
					 unsigned int index)
{
	return &dev->_tx[index];
}

static inline void netdev_for_each_tx_queue(struct net_device *dev,
					    void (*f)(struct net_device *,
						      struct netdev_queue *,
						      void *),
					    void *arg)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++)
		f(dev, &dev->_tx[i], arg);
}

/*
 * Net namespace inlines
 */
static inline
struct net *dev_net(const struct net_device *dev)
{
#ifdef CONFIG_NET_NS
	return dev->nd_net;
#else
	return &init_net;
#endif
}

//用来切换网络命名空间
static inline
void dev_net_set(struct net_device *dev, struct net *net)
{
#ifdef CONFIG_NET_NS
	release_net(dev->nd_net);
	dev->nd_net = hold_net(net);
#endif
}

static inline bool netdev_uses_dsa_tags(struct net_device *dev)
{
#ifdef CONFIG_NET_DSA_TAG_DSA
	if (dev->dsa_ptr != NULL)
		return dsa_uses_dsa_tags(dev->dsa_ptr);
#endif

	return 0;
}

static inline bool netdev_uses_trailer_tags(struct net_device *dev)
{
#ifdef CONFIG_NET_DSA_TAG_TRAILER
	if (dev->dsa_ptr != NULL)
		return dsa_uses_trailer_tags(dev->dsa_ptr);
#endif

	return 0;
}

/**
 *	netdev_priv - access network device private data
 *	@dev: network device
 *
 * Get network device private data
 */
 //获得alloc_netdev_mq()分配的私有数据
static inline void *netdev_priv(const struct net_device *dev)
{
	return (char *)dev + ALIGN(sizeof(struct net_device), NETDEV_ALIGN);
}

/* Set the sysfs physical device reference for the network logical device
 * if set prior to registration will cause a symlink during initialization.
 */
#define SET_NETDEV_DEV(net, pdev)	((net)->dev.parent = (pdev))

/* Set the sysfs device type for the network logical device to allow
 * fin grained indentification of different network device types. For
 * example Ethernet, Wirelss LAN, Bluetooth, WiMAX etc.
 */
#define SET_NETDEV_DEVTYPE(net, devtype)	((net)->dev.type = (devtype))

/**
 *	netif_napi_add - initialize a napi context
 *	@dev:  network device
 *	@napi: napi context
 *	@poll: polling function
 *	@weight: default weight
 *
 * netif_napi_add() must be used to initialize a napi context prior to calling
 * *any* of the other napi related functions.
 */
void netif_napi_add(struct net_device *dev, struct napi_struct *napi,
		    int (*poll)(struct napi_struct *, int), int weight);

/**
 *  netif_napi_del - remove a napi context
 *  @napi: napi context
 *
 *  netif_napi_del() removes a napi context from the network device napi list
 */
void netif_napi_del(struct napi_struct *napi);

struct napi_gro_cb {
	/* Virtual address of skb_shinfo(skb)->frags[0].page + offset. */
	void *frag0;

	/* Length of frag0. */
	unsigned int frag0_len;

	/* This indicates where we are processing relative to skb->data. */
	int data_offset;

	/* This is non-zero if the packet may be of the same flow. */
	int same_flow;

	/* This is non-zero if the packet cannot be merged with the new skb. */
	int flush;

	/* Number of segments aggregated. */
	int count;

	/* Free the skb? */
	int free;
};

#define NAPI_GRO_CB(skb) ((struct napi_gro_cb *)(skb)->cb)

//网络层协议结构
//每个网络层协议对应一个此结构
//内核将所有网络层协议构成一个链表
struct packet_type {
	__be16			type;	/* htons(ether_type).type 成员保存了网络层协议类型，ETH_P_IP、ETH_P_ARP */
	struct net_device	*dev;	/* 网络接口设备 当为NULL表示所有的设备 */
	int			(*func) (struct sk_buff *, //协议处理函数func 成员就是钩子函数了，如 ip_rcv()、arp_rcv()
					 struct net_device *,
					 struct packet_type *,
					 struct net_device *);
	struct sk_buff		*(*gso_segment)(struct sk_buff *skb,
						int features);
	int			(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff		**(*gro_receive)(struct sk_buff **head,
					       struct sk_buff *skb);
	int			(*gro_complete)(struct sk_buff *skb);
	
	void			*af_packet_priv;//AF_PACKET 的私有数据 packet_rcv()用于保存sock
	
	struct list_head	list; //组成链表
};

#include <linux/interrupt.h>
#include <linux/notifier.h>

extern rwlock_t				dev_base_lock;		/* Device list lock */


#define for_each_netdev(net, d)		\
		list_for_each_entry(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_safe(net, d, n)	\
		list_for_each_entry_safe(d, n, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue(net, d)		\
		list_for_each_entry_continue(d, &(net)->dev_base_head, dev_list)
#define net_device_entry(lh)	list_entry(lh, struct net_device, dev_list)

static inline struct net_device *next_net_device(struct net_device *dev)
{
	struct list_head *lh;
	struct net *net;

	net = dev_net(dev);
	lh = dev->dev_list.next;
	return lh == &net->dev_base_head ? NULL : net_device_entry(lh);
}

static inline struct net_device *first_net_device(struct net *net)
{
	return list_empty(&net->dev_base_head) ? NULL :
		net_device_entry(net->dev_base_head.next);
}

extern int 			netdev_boot_setup_check(struct net_device *dev);
extern unsigned long		netdev_boot_base(const char *prefix, int unit);
extern struct net_device    *dev_getbyhwaddr(struct net *net, unsigned short type, char *hwaddr);
extern struct net_device *dev_getfirstbyhwtype(struct net *net, unsigned short type);
extern struct net_device *__dev_getfirstbyhwtype(struct net *net, unsigned short type);

//链路层模块提供给网络层模块进行网络协议注册注销的函数
extern void		dev_add_pack(struct packet_type *pt);
extern void		dev_remove_pack(struct packet_type *pt);

extern void		__dev_remove_pack(struct packet_type *pt);

extern struct net_device	*dev_get_by_flags(struct net *net, unsigned short flags,
						  unsigned short mask);

//返回由参数指定的设备,网络中每个设备由net_device表示
//不同的网络设备有不同的表示名称
extern struct net_device	*dev_get_by_name(struct net *net, const char *name);
extern struct net_device	*__dev_get_by_name(struct net *net, const char *name);
extern int		dev_alloc_name(struct net_device *dev, const char *name);

//
extern int		dev_open(struct net_device *dev);
extern int		dev_close(struct net_device *dev);

extern void		dev_disable_lro(struct net_device *dev);
extern int		dev_queue_xmit(struct sk_buff *skb);
extern int		register_netdevice(struct net_device *dev);
extern void		unregister_netdevice(struct net_device *dev);
extern void		free_netdev(struct net_device *dev);
extern void		synchronize_net(void);
extern int 		register_netdevice_notifier(struct notifier_block *nb);
extern int		unregister_netdevice_notifier(struct notifier_block *nb);
extern int		init_dummy_netdev(struct net_device *dev);
extern void		netdev_resync_ops(struct net_device *dev);

extern int call_netdevice_notifiers(unsigned long val, struct net_device *dev);
extern struct net_device	*dev_get_by_index(struct net *net, int ifindex);
extern struct net_device	*__dev_get_by_index(struct net *net, int ifindex);
extern int		dev_restart(struct net_device *dev);
#ifdef CONFIG_NETPOLL_TRAP
extern int		netpoll_trap(void);
#endif
extern int	       skb_gro_receive(struct sk_buff **head,
				       struct sk_buff *skb);
extern void	       skb_gro_reset_offset(struct sk_buff *skb);

static inline unsigned int skb_gro_offset(const struct sk_buff *skb)
{
	return NAPI_GRO_CB(skb)->data_offset;
}

static inline unsigned int skb_gro_len(const struct sk_buff *skb)
{
	return skb->len - NAPI_GRO_CB(skb)->data_offset;
}

static inline void skb_gro_pull(struct sk_buff *skb, unsigned int len)
{
	NAPI_GRO_CB(skb)->data_offset += len;
}

static inline void *skb_gro_header_fast(struct sk_buff *skb,
					unsigned int offset)
{
	return NAPI_GRO_CB(skb)->frag0 + offset;
}

static inline int skb_gro_header_hard(struct sk_buff *skb, unsigned int hlen)
{
	return NAPI_GRO_CB(skb)->frag0_len < hlen;
}

static inline void *skb_gro_header_slow(struct sk_buff *skb, unsigned int hlen,
					unsigned int offset)
{
	NAPI_GRO_CB(skb)->frag0 = NULL;
	NAPI_GRO_CB(skb)->frag0_len = 0;
	return pskb_may_pull(skb, hlen) ? skb->data + offset : NULL;
}

static inline void *skb_gro_mac_header(struct sk_buff *skb)
{
	return NAPI_GRO_CB(skb)->frag0 ?: skb_mac_header(skb);
}

static inline void *skb_gro_network_header(struct sk_buff *skb)
{
	return (NAPI_GRO_CB(skb)->frag0 ?: skb->data) +
	       skb_network_offset(skb);
}

static inline int dev_hard_header(struct sk_buff *skb, 
	                                       struct net_device *dev,
				                           unsigned short type,
				                           const void *daddr, const void *saddr,
				                           unsigned len)
{                           //eth_header() 
	if (!dev->header_ops || !dev->header_ops->create)
		return 0;

	return dev->header_ops->create(skb, dev, type, daddr, saddr, len);
}

static inline int dev_parse_header(const struct sk_buff *skb,
				   unsigned char *haddr)
{
	const struct net_device *dev = skb->dev;

	if (!dev->header_ops || !dev->header_ops->parse)
		return 0;
	return dev->header_ops->parse(skb, haddr);
}

typedef int gifconf_func_t(struct net_device * dev, char __user * bufptr, int len);
extern int		register_gifconf(unsigned int family, gifconf_func_t * gifconf);
static inline int unregister_gifconf(unsigned int family)
{
	return register_gifconf(family, NULL);
}

/*
 * Incoming packets are placed on per-cpu queues so that
 * no locking is needed.
 */
 /*
非NAPI:      
	  MAC每收到一个包或者BD即产生一个中断，缺点是网络PPS高时，CPU将大部分时间耗费在了MAC中断上。
netpoll:
      轮询收包，实时性差。
NAPI:      
中断＋轮询方式，MAC收到第一个包时产生中断，收包程序中关闭该中断，
	启动轮询收包，知道收完buffer中的所有包或者是netdev_max_backlog个包之后，重新打开中断
*/
/*初始化在net_dev_init中*/
struct softnet_data
{
	struct Qdisc		*output_queue; //此处是有空间能够接收从上层传输下来的数据的设备列表
	                                   //连接到此队列的成员net_device{}->_tx[index]=netdev_queue{}->qdisc=Qdisc{}->next_sched
	struct sk_buff_head	input_pkt_queue;//当输入帧被驱动取得之前，就保存在这个队列里，（不适用与napi驱动，napi有自己的私有队列）
	struct list_head	poll_list;//表示有输入帧待处理的设备链表。 链表中的设备都有输入帧等待被处理
	struct sk_buff		*completion_queue; //表示已经成功被传递出的帧的链表。

	struct napi_struct	backlog;//用来兼容非napi的驱动。
};

DECLARE_PER_CPU(struct softnet_data,softnet_data);

#define HAVE_NETIF_QUEUE

extern void __netif_schedule(struct Qdisc *q);

static inline void netif_schedule_queue(struct netdev_queue *txq)
{
	if (!test_bit(__QUEUE_STATE_XOFF, &txq->state))
		__netif_schedule(txq->qdisc);
}

static inline void netif_tx_schedule_all(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++)
		netif_schedule_queue(netdev_get_tx_queue(dev, i));
}

static inline void netif_tx_start_queue(struct netdev_queue *dev_queue)
{
	clear_bit(__QUEUE_STATE_XOFF, &dev_queue->state);
}

/**
 *	netif_start_queue - allow transmit
 *	@dev: network device
 *
 *	Allow upper layers to call the device hard_start_xmit routine.
 */
 //让驱动程序告诉内核网络子系统高层,当前底层的网络设备可以继续传输数据包
 //开启设备传输
static inline void netif_start_queue(struct net_device *dev)
{
	netif_tx_start_queue(netdev_get_tx_queue(dev, 0));
}

static inline void netif_tx_start_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_start_queue(txq);
	}
}

static inline void netif_tx_wake_queue(struct netdev_queue *dev_queue)
{
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap()) {
		netif_tx_start_queue(dev_queue);
		return;
	}
#endif
    //当前dev_queue->state是否为__QUEUE_STATE_XOFF 不是返回,是消除__QUEUE_STATE_XOFF
	if (test_and_clear_bit(__QUEUE_STATE_XOFF, &dev_queue->state))
		__netif_schedule(dev_queue->qdisc);
}

/**
 *	netif_wake_queue - restart transmit
 *	@dev: network device
 *
 *	Allow upper layers to call the device hard_start_xmit routine.
 *	Used for flow control when transmit resources are available.
 */
static inline void netif_wake_queue(struct net_device *dev)
{
	netif_tx_wake_queue(netdev_get_tx_queue(dev, 0));
}

static inline void netif_tx_wake_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_wake_queue(txq);
	}
}

static inline void netif_tx_stop_queue(struct netdev_queue *dev_queue)
{
	set_bit(__QUEUE_STATE_XOFF, &dev_queue->state);
}

/**
 *	netif_stop_queue - stop transmitted packets
 *	@dev: network device
 *
 *	Stop upper layers calling the device hard_start_xmit routine.
 *	Used for flow control when transmit resources are unavailable.
 */
 //让驱动程序告诉内核网络子系统高层,当前底层的网络设备无法继续传输数据包
 //关闭设备传输
static inline void netif_stop_queue(struct net_device *dev)
{
	netif_tx_stop_queue(netdev_get_tx_queue(dev, 0));
}

static inline void netif_tx_stop_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_stop_queue(txq);
	}
}

//返回出口队列的状态
static inline int netif_tx_queue_stopped(const struct netdev_queue *dev_queue)
{
	return test_bit(__QUEUE_STATE_XOFF, &dev_queue->state);
}

/**
 *	netif_queue_stopped - test if transmit queue is flowblocked
 *	@dev: network device
 *
 *	Test if transmit queue on device is currently unable to send.
 */
static inline int netif_queue_stopped(const struct net_device *dev)
{
	return netif_tx_queue_stopped(netdev_get_tx_queue(dev, 0));
}

static inline int netif_tx_queue_frozen(const struct netdev_queue *dev_queue)
{
	return test_bit(__QUEUE_STATE_FROZEN, &dev_queue->state);
}

/**
 *	netif_running - test if up
 *	@dev: network device
 *
 *	Test if the device has been brought up.
 */
static inline int netif_running(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_START, &dev->state);
}

/*
 * Routines to manage the subqueues on a device.  We only need start
 * stop, and a check if it's stopped.  All other device management is
 * done at the overall netdevice level.
 * Also test the device if we're multiqueue.
 */

/**
 *	netif_start_subqueue - allow sending packets on subqueue
 *	@dev: network device
 *	@queue_index: sub queue index
 *
 * Start individual transmit queue of a device with multiple transmit queues.
 */
static inline void netif_start_subqueue(struct net_device *dev, u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);

	netif_tx_start_queue(txq);
}

/**
 *	netif_stop_subqueue - stop sending packets on subqueue
 *	@dev: network device
 *	@queue_index: sub queue index
 *
 * Stop individual transmit queue of a device with multiple transmit queues.
 */
static inline void netif_stop_subqueue(struct net_device *dev, u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	netif_tx_stop_queue(txq);
}

/**
 *	netif_subqueue_stopped - test status of subqueue
 *	@dev: network device
 *	@queue_index: sub queue index
 *
 * Check individual transmit queue of a device with multiple transmit queues.
 */
static inline int __netif_subqueue_stopped(const struct net_device *dev,
					 u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);

	return netif_tx_queue_stopped(txq);
}

static inline int netif_subqueue_stopped(const struct net_device *dev,
					 struct sk_buff *skb)
{
	return __netif_subqueue_stopped(dev, skb_get_queue_mapping(skb));
}

/**
 *	netif_wake_subqueue - allow sending packets on subqueue
 *	@dev: network device
 *	@queue_index: sub queue index
 *
 * Resume individual transmit queue of a device with multiple transmit queues.
 */
static inline void netif_wake_subqueue(struct net_device *dev, u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	if (test_and_clear_bit(__QUEUE_STATE_XOFF, &txq->state))
		__netif_schedule(txq->qdisc);
}

/**
 *	netif_is_multiqueue - test if device has multiple transmit queues
 *	@dev: network device
 *
 * Check if device has multiple transmit queues
 */
static inline int netif_is_multiqueue(const struct net_device *dev)
{
	return (dev->num_tx_queues > 1);
}

/* Use this variant when it is known for sure that it
 * is executing from hardware interrupt context or with hardware interrupts
 * disabled.
 */
extern void dev_kfree_skb_irq(struct sk_buff *skb);

/* Use this variant in places where it could be invoked
 * from either hardware interrupt or other context, with hardware interrupts
 * either disabled or enabled.
 */
extern void dev_kfree_skb_any(struct sk_buff *skb);

#define HAVE_NETIF_RX 1
extern int		netif_rx(struct sk_buff *skb);
extern int		netif_rx_ni(struct sk_buff *skb);
#define HAVE_NETIF_RECEIVE_SKB 1
extern int		netif_receive_skb(struct sk_buff *skb);
extern void		napi_gro_flush(struct napi_struct *napi);
extern int		dev_gro_receive(struct napi_struct *napi,
					struct sk_buff *skb);
extern int		napi_skb_finish(int ret, struct sk_buff *skb);
extern int		napi_gro_receive(struct napi_struct *napi,
					 struct sk_buff *skb);
extern void		napi_reuse_skb(struct napi_struct *napi,
				       struct sk_buff *skb);
extern struct sk_buff *	napi_get_frags(struct napi_struct *napi);
extern int		napi_frags_finish(struct napi_struct *napi,
					  struct sk_buff *skb, int ret);
extern struct sk_buff *	napi_frags_skb(struct napi_struct *napi);
extern int		napi_gro_frags(struct napi_struct *napi);

static inline void napi_free_frags(struct napi_struct *napi)
{
	kfree_skb(napi->skb);
	napi->skb = NULL;
}

extern void		netif_nit_deliver(struct sk_buff *skb);
extern int		dev_valid_name(const char *name);
extern int		dev_ioctl(struct net *net, unsigned int cmd, void __user *);
extern int		dev_ethtool(struct net *net, struct ifreq *);
extern unsigned		dev_get_flags(const struct net_device *);
extern int		dev_change_flags(struct net_device *, unsigned);
extern int		dev_change_name(struct net_device *, const char *);
extern int		dev_set_alias(struct net_device *, const char *, size_t);
extern int		dev_change_net_namespace(struct net_device *,
						 struct net *, const char *);
extern int		dev_set_mtu(struct net_device *, int);
extern int		dev_set_mac_address(struct net_device *,
					    struct sockaddr *);
extern int		dev_hard_start_xmit(struct sk_buff *skb,
					    struct net_device *dev,
					    struct netdev_queue *txq);

extern int		netdev_budget;

/* Called by rtnetlink.c:rtnl_unlock() */
extern void netdev_run_todo(void);

/**
 *	dev_put - release reference to device
 *	@dev: network device
 *
 * Release reference to device to allow it to be freed.
 */
static inline void dev_put(struct net_device *dev)
{
	atomic_dec(&dev->refcnt);
}

/**
 *	dev_hold - get reference to device
 *	@dev: network device
 *
 * Hold reference to device to keep it from being freed.
 */
static inline void dev_hold(struct net_device *dev)
{
	atomic_inc(&dev->refcnt);
}

/* Carrier loss detection, dial on demand. The functions netif_carrier_on
 * and _off may be called from IRQ context, but it is caller
 * who is responsible for serialization of these calls.
 *
 * The name carrier is inappropriate, these functions should really be
 * called netif_lowerlayer_*() because they represent the state of any
 * kind of lower layer not just hardware media.
 */

extern void linkwatch_fire_event(struct net_device *dev);

/**
 *	netif_carrier_ok - test if carrier present
 *	@dev: network device
 *
 * Check if carrier is present on device
 */
static inline int netif_carrier_ok(const struct net_device *dev)
{
	return !test_bit(__LINK_STATE_NOCARRIER, &dev->state);
}

extern unsigned long dev_trans_start(struct net_device *dev);

extern void __netdev_watchdog_up(struct net_device *dev);

extern void netif_carrier_on(struct net_device *dev);

extern void netif_carrier_off(struct net_device *dev);

extern void netif_notify_peers(struct net_device *dev);

/**
 *	netif_dormant_on - mark device as dormant.
 *	@dev: network device
 *
 * Mark device as dormant (as per RFC2863).
 *
 * The dormant state indicates that the relevant interface is not
 * actually in a condition to pass packets (i.e., it is not 'up') but is
 * in a "pending" state, waiting for some external event.  For "on-
 * demand" interfaces, this new state identifies the situation where the
 * interface is waiting for events to place it in the up state.
 *
 */
static inline void netif_dormant_on(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_DORMANT, &dev->state))
		linkwatch_fire_event(dev);
}

/**
 *	netif_dormant_off - set device as not dormant.
 *	@dev: network device
 *
 * Device is not in dormant state.
 */
static inline void netif_dormant_off(struct net_device *dev)
{
	if (test_and_clear_bit(__LINK_STATE_DORMANT, &dev->state))
		linkwatch_fire_event(dev);
}

/**
 *	netif_dormant - test if carrier present
 *	@dev: network device
 *
 * Check if carrier is present on device
 */
static inline int netif_dormant(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_DORMANT, &dev->state);
}


/**
 *	netif_oper_up - test if device is operational
 *	@dev: network device
 *
 * Check if carrier is operational
 */
static inline int netif_oper_up(const struct net_device *dev) {
	return (dev->operstate == IF_OPER_UP ||
		dev->operstate == IF_OPER_UNKNOWN /* backward compat */);
}

/**
 *	netif_device_present - is device available or removed
 *	@dev: network device
 *
 * Check if device has not been removed from system.
 */
static inline int netif_device_present(struct net_device *dev)
{
	return test_bit(__LINK_STATE_PRESENT, &dev->state);
}

extern void netif_device_detach(struct net_device *dev);

extern void netif_device_attach(struct net_device *dev);

/*
 * Network interface message level settings
 */
#define HAVE_NETIF_MSG 1

enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};

#define netif_msg_drv(p)	((p)->msg_enable & NETIF_MSG_DRV)
#define netif_msg_probe(p)	((p)->msg_enable & NETIF_MSG_PROBE)
#define netif_msg_link(p)	((p)->msg_enable & NETIF_MSG_LINK)
#define netif_msg_timer(p)	((p)->msg_enable & NETIF_MSG_TIMER)
#define netif_msg_ifdown(p)	((p)->msg_enable & NETIF_MSG_IFDOWN)
#define netif_msg_ifup(p)	((p)->msg_enable & NETIF_MSG_IFUP)
#define netif_msg_rx_err(p)	((p)->msg_enable & NETIF_MSG_RX_ERR)
#define netif_msg_tx_err(p)	((p)->msg_enable & NETIF_MSG_TX_ERR)
#define netif_msg_tx_queued(p)	((p)->msg_enable & NETIF_MSG_TX_QUEUED)
#define netif_msg_intr(p)	((p)->msg_enable & NETIF_MSG_INTR)
#define netif_msg_tx_done(p)	((p)->msg_enable & NETIF_MSG_TX_DONE)
#define netif_msg_rx_status(p)	((p)->msg_enable & NETIF_MSG_RX_STATUS)
#define netif_msg_pktdata(p)	((p)->msg_enable & NETIF_MSG_PKTDATA)
#define netif_msg_hw(p)		((p)->msg_enable & NETIF_MSG_HW)
#define netif_msg_wol(p)	((p)->msg_enable & NETIF_MSG_WOL)

static inline u32 netif_msg_init(int debug_value, int default_msg_enable_bits)
{
	/* use default */
	if (debug_value < 0 || debug_value >= (sizeof(u32) * 8))
		return default_msg_enable_bits;
	if (debug_value == 0)	/* no output */
		return 0;
	/* set low N bits */
	return (1 << debug_value) - 1;
}

static inline void __netif_tx_lock(struct netdev_queue *txq, int cpu)
{
	spin_lock(&txq->_xmit_lock);
	txq->xmit_lock_owner = cpu;
}

static inline void __netif_tx_lock_bh(struct netdev_queue *txq)
{
	spin_lock_bh(&txq->_xmit_lock);
	txq->xmit_lock_owner = smp_processor_id();
}

static inline int __netif_tx_trylock(struct netdev_queue *txq)
{
	int ok = spin_trylock(&txq->_xmit_lock);
	if (likely(ok))
		txq->xmit_lock_owner = smp_processor_id();
	return ok;
}

static inline void __netif_tx_unlock(struct netdev_queue *txq)
{
	txq->xmit_lock_owner = -1;
	spin_unlock(&txq->_xmit_lock);
}

static inline void __netif_tx_unlock_bh(struct netdev_queue *txq)
{
	txq->xmit_lock_owner = -1;
	spin_unlock_bh(&txq->_xmit_lock);
}

static inline void txq_trans_update(struct netdev_queue *txq)
{
	if (txq->xmit_lock_owner != -1)
		txq->trans_start = jiffies;
}

/**
 *	netif_tx_lock - grab network device transmit lock
 *	@dev: network device
 *
 * Get network device transmit lock
 */
static inline void netif_tx_lock(struct net_device *dev)
{
	unsigned int i;
	int cpu;

	spin_lock(&dev->tx_global_lock);
	cpu = smp_processor_id();
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		/* We are the only thread of execution doing a
		 * freeze, but we have to grab the _xmit_lock in
		 * order to synchronize with threads which are in
		 * the ->hard_start_xmit() handler and already
		 * checked the frozen bit.
		 */
		__netif_tx_lock(txq, cpu);
		set_bit(__QUEUE_STATE_FROZEN, &txq->state);
		__netif_tx_unlock(txq);
	}
}

static inline void netif_tx_lock_bh(struct net_device *dev)
{
	local_bh_disable();
	netif_tx_lock(dev);
}

static inline void netif_tx_unlock(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		/* No need to grab the _xmit_lock here.  If the
		 * queue is not stopped for another reason, we
		 * force a schedule.
		 */
		clear_bit(__QUEUE_STATE_FROZEN, &txq->state);
		netif_schedule_queue(txq);
	}
	spin_unlock(&dev->tx_global_lock);
}

static inline void netif_tx_unlock_bh(struct net_device *dev)
{
	netif_tx_unlock(dev);
	local_bh_enable();
}

#define HARD_TX_LOCK(dev, txq, cpu) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_lock(txq, cpu);		\
	}						\
}

#define HARD_TX_UNLOCK(dev, txq) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_unlock(txq);			\
	}						\
}

static inline void netif_tx_disable(struct net_device *dev)
{
	unsigned int i;
	int cpu;

	local_bh_disable();
	cpu = smp_processor_id();
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		__netif_tx_lock(txq, cpu);
		netif_tx_stop_queue(txq);
		__netif_tx_unlock(txq);
	}
	local_bh_enable();
}

static inline void netif_addr_lock(struct net_device *dev)
{
	spin_lock(&dev->addr_list_lock);
}

static inline void netif_addr_lock_bh(struct net_device *dev)
{
	spin_lock_bh(&dev->addr_list_lock);
}

static inline void netif_addr_unlock(struct net_device *dev)
{
	spin_unlock(&dev->addr_list_lock);
}

static inline void netif_addr_unlock_bh(struct net_device *dev)
{
	spin_unlock_bh(&dev->addr_list_lock);
}

/*
 * dev_addrs walker. Should be used only for read access. Call with
 * rcu_read_lock held.
 */
#define for_each_dev_addr(dev, ha) \
		list_for_each_entry_rcu(ha, &dev->dev_addrs.list, list)

/* These functions live elsewhere (drivers/net/net_init.c, but related) */

extern void		ether_setup(struct net_device *dev);

/* Support for loadable net-drivers */
extern struct net_device *alloc_netdev_mq(int sizeof_priv, const char *name,
				       void (*setup)(struct net_device *),
				       unsigned int queue_count);
#define alloc_netdev(sizeof_priv, name, setup) \
	alloc_netdev_mq(sizeof_priv, name, setup, 1)
extern int		register_netdev(struct net_device *dev);
extern void		unregister_netdev(struct net_device *dev);

/* Functions used for device addresses handling */
extern int dev_addr_add(struct net_device *dev, unsigned char *addr,
			unsigned char addr_type);
extern int dev_addr_del(struct net_device *dev, unsigned char *addr,
			unsigned char addr_type);
extern int dev_addr_add_multiple(struct net_device *to_dev,
				 struct net_device *from_dev,
				 unsigned char addr_type);
extern int dev_addr_del_multiple(struct net_device *to_dev,
				 struct net_device *from_dev,
				 unsigned char addr_type);

/* Functions used for secondary unicast and multicast support */
extern void		dev_set_rx_mode(struct net_device *dev);
extern void		__dev_set_rx_mode(struct net_device *dev);
extern int		dev_unicast_delete(struct net_device *dev, void *addr);
extern int		dev_unicast_add(struct net_device *dev, void *addr);
extern int		dev_unicast_sync(struct net_device *to, struct net_device *from);
extern void		dev_unicast_unsync(struct net_device *to, struct net_device *from);
extern int 		dev_mc_delete(struct net_device *dev, void *addr, int alen, int all);
extern int		dev_mc_add(struct net_device *dev, void *addr, int alen, int newonly);
extern int		dev_mc_sync(struct net_device *to, struct net_device *from);
extern void		dev_mc_unsync(struct net_device *to, struct net_device *from);
extern int 		__dev_addr_delete(struct dev_addr_list **list, int *count, void *addr, int alen, int all);
extern int		__dev_addr_add(struct dev_addr_list **list, int *count, void *addr, int alen, int newonly);
extern int		__dev_addr_sync(struct dev_addr_list **to, int *to_count, struct dev_addr_list **from, int *from_count);
extern void		__dev_addr_unsync(struct dev_addr_list **to, int *to_count, struct dev_addr_list **from, int *from_count);
extern int		dev_set_promiscuity(struct net_device *dev, int inc);
extern int		dev_set_allmulti(struct net_device *dev, int inc);
extern void		netdev_state_change(struct net_device *dev);
extern void		netdev_bonding_change(struct net_device *dev,
					      unsigned long event);
extern void		netdev_features_change(struct net_device *dev);
/* Load a device via the kmod */
extern void		dev_load(struct net *net, const char *name);
extern void		dev_mcast_init(void);
extern const struct net_device_stats *dev_get_stats(struct net_device *dev);

extern int		netdev_max_backlog;// /proc/sys/net/core/netdev_max_backlog
extern int		weight_p;          //  /proc/sys/net/core/dev_weight
extern int		netdev_set_master(struct net_device *dev, struct net_device *master);
extern int skb_checksum_help(struct sk_buff *skb);
extern struct sk_buff *skb_gso_segment(struct sk_buff *skb, int features);
#ifdef CONFIG_BUG
extern void netdev_rx_csum_fault(struct net_device *dev);
#else
static inline void netdev_rx_csum_fault(struct net_device *dev)
{
}
#endif
/* rx skb timestamps */
extern void		net_enable_timestamp(void);
extern void		net_disable_timestamp(void);

#ifdef CONFIG_PROC_FS
extern void *dev_seq_start(struct seq_file *seq, loff_t *pos);
extern void *dev_seq_next(struct seq_file *seq, void *v, loff_t *pos);
extern void dev_seq_stop(struct seq_file *seq, void *v);
#endif

extern int netdev_class_create_file(struct class_attribute *class_attr);
extern void netdev_class_remove_file(struct class_attribute *class_attr);

extern char *netdev_drivername(const struct net_device *dev, char *buffer, int len);

extern void linkwatch_run_queue(void);

unsigned long netdev_increment_features(unsigned long all, unsigned long one,
					unsigned long mask);
unsigned long netdev_fix_features(unsigned long features, const char *name);

static inline int net_gso_ok(int features, int gso_type)
{
	int feature = gso_type << NETIF_F_GSO_SHIFT;
	return (features & feature) == feature;
}

static inline int skb_gso_ok(struct sk_buff *skb, int features)
{
	return  net_gso_ok(features, skb_shinfo(skb)->gso_type) &&
	       (!skb_has_frags(skb) || (features & NETIF_F_FRAGLIST));
}

static inline int netif_needs_gso(struct net_device *dev, struct sk_buff *skb)
{
	return skb_is_gso(skb) &&
	       (!skb_gso_ok(skb, dev->features) || unlikely(skb->ip_summed != CHECKSUM_PARTIAL));
}

static inline void netif_set_gso_max_size(struct net_device *dev,
					  unsigned int size)
{
	dev->gso_max_size = size;
}

static inline void skb_bond_set_mac_by_master(struct sk_buff *skb,
					      struct net_device *master)
{
	if (skb->pkt_type == PACKET_HOST) {
		u16 *dest = (u16 *) eth_hdr(skb)->h_dest;

		memcpy(dest, master->dev_addr, ETH_ALEN);
	}
}

/* On bonding slaves other than the currently active slave, suppress
 * duplicates except for 802.3ad ETH_P_SLOW, alb non-mcast/bcast, and
 * ARP on active-backup slaves with arp_validate enabled.
 */
static inline int skb_bond_should_drop(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct net_device *master = dev->master;

	if (master) {
		if (master->priv_flags & IFF_MASTER_ARPMON)
			dev->last_rx = jiffies;

		if ((master->priv_flags & IFF_MASTER_ALB) && master->br_port) {
			/* Do address unmangle. The local destination address
			 * will be always the one master has. Provides the right
			 * functionality in a bridge.
			 */
			skb_bond_set_mac_by_master(skb, master);
		}

		if (dev->priv_flags & IFF_SLAVE_INACTIVE) {
			if ((dev->priv_flags & IFF_SLAVE_NEEDARP) &&
			    skb->protocol == __cpu_to_be16(ETH_P_ARP))
				return 0;

			if (master->priv_flags & IFF_MASTER_ALB) {
				if (skb->pkt_type != PACKET_BROADCAST &&
				    skb->pkt_type != PACKET_MULTICAST)
					return 0;
			}
			if (master->priv_flags & IFF_MASTER_8023AD &&
			    skb->protocol == __cpu_to_be16(ETH_P_SLOW))
				return 0;

			return 1;
		}
	}
	return 0;
}

extern struct pernet_operations __net_initdata loopback_net_ops;

static inline int dev_ethtool_get_settings(struct net_device *dev,
					   struct ethtool_cmd *cmd)
{
	if (!dev->ethtool_ops || !dev->ethtool_ops->get_settings)
		return -EOPNOTSUPP;
	return dev->ethtool_ops->get_settings(dev, cmd);
}

static inline u32 dev_ethtool_get_rx_csum(struct net_device *dev)
{
	if (!dev->ethtool_ops || !dev->ethtool_ops->get_rx_csum)
		return 0;
	return dev->ethtool_ops->get_rx_csum(dev);
}

static inline u32 dev_ethtool_get_flags(struct net_device *dev)
{
	if (!dev->ethtool_ops || !dev->ethtool_ops->get_flags)
		return 0;
	return dev->ethtool_ops->get_flags(dev);
}
#endif /* __KERNEL__ */

#endif	/* _LINUX_NETDEVICE_H */
