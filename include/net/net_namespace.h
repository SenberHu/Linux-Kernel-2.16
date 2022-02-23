/*
 * Operations on the network namespace
 */
#ifndef __NET_NET_NAMESPACE_H
#define __NET_NET_NAMESPACE_H

#include <asm/atomic.h>
#include <linux/workqueue.h>
#include <linux/list.h>

#include <net/netns/core.h>
#include <net/netns/mib.h>
#include <net/netns/unix.h>
#include <net/netns/packet.h>
#include <net/netns/ipv4.h>
#include <net/netns/ipv6.h>
#include <net/netns/dccp.h>
#include <net/netns/x_tables.h>
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#include <net/netns/conntrack.h>
#endif
#include <net/netns/xfrm.h>

struct proc_dir_entry;
struct net_device;
struct sock;
struct ctl_table_header;
struct net_generic;
struct sock;

// struct net 结构体表示的内核中的网络命名空间(net_namespace)
struct net {
                          //网络命名空间的引用计数器
	atomic_t		count;		/* To decided when the network
						 *  namespace should be freed.
						 */
#ifdef NETNS_REFCNT_DEBUG
	atomic_t		use_count;	/* To track references we
						 * destroy on demand
						 */
#endif
   
    //用于将内核中的所有的网络命名空间以双链表的形式组织起来，即将
    //所有的struct net结构体组织成双链表
    //表头为net_namespace_list
	struct list_head	list;		/*  list of network namespaces  */

	 
	struct work_struct	work;		/* work struct for freeing */

	struct proc_dir_entry 	*proc_net;//表示网络命名空间procfs条目/proc/net,每个网络命名空间都维护这自己的profs条目
	                                  //看proc_net_ns_init() 
	                                  
	struct proc_dir_entry 	*proc_net_stat;//表示网络命名空间procfs统计信息条目 /proc/net/stat

#ifdef CONFIG_SYSCTL
	struct ctl_table_set	sysctls;
#endif

   //loopback_net_init()
	struct net_device       *loopback_dev;          /* The loopback 表示环回设备,网络命名空间创建时只有一个网络设备,环回设备*/

    //因为在一个网络命名空间中，可能有多个网络设备,而这些网络设备也是
    //通过双链表的形式组织起来的。而dev_base_head就是网络设备双链表
    //的链表头；对应net_device 中的dev_list
	struct list_head 	dev_base_head;

    //因为在一个网络命名空间中，每一个网络设备都有其设备名，而内核为了
    //能够根据网络设备名快速的找到相应的网络设备，使用了内核中常有的
    //哈希散列表来实现根据设备名来快速查找设备。
    //对应net_device 的name_list
	struct hlist_head 	*dev_name_head;

    //在一个网络设备命名空间中，每一个网络设备在系统中都会有一个唯一
    //的接口索引值(int ifindex),同样内核也是通过内核中的哈希散列表
    //来实现根据接口索引值快速查找网络设备。
    //对应net_device中的index_list
	struct hlist_head	*dev_index_head;

	/* core fib_rules */
	struct list_head	rules_ops;//路由规则

	
	spinlock_t		rules_mod_lock;

	struct sock 		*rtnl;			/* rtnetlink socket rtnetlink套接字用于 NETLINK_ROUTE*/
	struct sock		*genl_sock; //通用netlink套接字  

	struct netns_core	core;
	struct netns_mib	mib;
	struct netns_packet	packet;
	struct netns_unix	unx;
	struct netns_ipv4	ipv4; //用于ipv4子系统 包含ipv4特有的字段 
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct netns_ipv6	ipv6;
#endif

#if defined(CONFIG_IP_DCCP) || defined(CONFIG_IP_DCCP_MODULE)
	struct netns_dccp	dccp;
#endif

#ifdef CONFIG_NETFILTER
	struct netns_xt		xt;
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	struct netns_ct		ct;  //用于连接跟踪子系统
#endif

#endif

//用于实现IPsec的框架 xfrm 
#ifdef CONFIG_XFRM
	struct netns_xfrm	xfrm; //用于IPsec子系统
#endif

#ifdef CONFIG_WIRELESS_EXT
	struct sk_buff_head	wext_nlevents;
#endif
	struct net_generic	*gen;
};


#include <linux/seq_file_net.h>

/* Init's network namespace */
extern struct net init_net;

#ifdef CONFIG_NET
#define INIT_NET_NS(net_ns) .net_ns = &init_net,

extern struct net *copy_net_ns(unsigned long flags, struct net *net_ns);

#else /* CONFIG_NET */

#define INIT_NET_NS(net_ns)

static inline struct net *copy_net_ns(unsigned long flags, struct net *net_ns)
{
	/* There is nothing to copy so this is a noop */
	return net_ns;
}
#endif /* CONFIG_NET */


extern struct list_head net_namespace_list;

extern struct net *get_net_ns_by_pid(pid_t pid);

#ifdef CONFIG_NET_NS
extern void __put_net(struct net *net);

static inline struct net *get_net(struct net *net)
{
	atomic_inc(&net->count);
	return net;
}

static inline struct net *maybe_get_net(struct net *net)
{
	/* Used when we know struct net exists but we
	 * aren't guaranteed a previous reference count
	 * exists.  If the reference count is zero this
	 * function fails and returns NULL.
	 */
	if (!atomic_inc_not_zero(&net->count))
		net = NULL;
	return net;
}

static inline void put_net(struct net *net)
{
	if (atomic_dec_and_test(&net->count))
		__put_net(net);
}

static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return net1 == net2;
}
#else

static inline struct net *get_net(struct net *net)
{
	return net;
}

static inline void put_net(struct net *net)
{
}

static inline struct net *maybe_get_net(struct net *net)
{
	return net;
}

static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return 1;
}
#endif


#ifdef NETNS_REFCNT_DEBUG
static inline struct net *hold_net(struct net *net)
{
	if (net)
		atomic_inc(&net->use_count);
	return net;
}

static inline void release_net(struct net *net)
{
	if (net)
		atomic_dec(&net->use_count);
}
#else
static inline struct net *hold_net(struct net *net)
{
	return net;
}

static inline void release_net(struct net *net)
{
}
#endif

#ifdef CONFIG_NET_NS

static inline void write_pnet(struct net **pnet, struct net *net)
{
	*pnet = net;
}

static inline struct net *read_pnet(struct net * const *pnet)
{
	return *pnet;
}

#else

#define write_pnet(pnet, net)	do { (void)(net);} while (0)
#define read_pnet(pnet)		(&init_net)

#endif

//遍历内核中的所有的网络命名空间
#define for_each_net(VAR)				\
	list_for_each_entry(VAR, &net_namespace_list, list)

#define for_each_net_rcu(VAR)				\
	list_for_each_entry_rcu(VAR, &net_namespace_list, list)

#ifdef CONFIG_NET_NS
#define __net_init
#define __net_exit
#define __net_initdata
#else
#define __net_init	__init
#define __net_exit	__exit_refok
#define __net_initdata	__initdata
#endif

//为了支持每个网络设备和网络子系统有独特的网络命名空间数据
struct pernet_operations {
	struct list_head list;
	int (*init)(struct net *net);
	void (*exit)(struct net *net);
};

/*
 * Use these carefully.  If you implement a network device and it
 * needs per network namespace operations use device pernet operations,
 * otherwise use pernet subsys operations.
 *
 * Network interfaces need to be removed from a dying netns _before_
 * subsys notifiers can be called, as most of the network code cleanup
 * (which is done from subsys notifiers) runs with the assumption that
 * dev_remove_pack has been called so no new packets will arrive during
 * and after the cleanup functions have been called.  dev_remove_pack
 * is not per namespace so instead the guarantee of no more packets
 * arriving in a network namespace is provided by ensuring that all
 * network devices and all sockets have left the network namespace
 * before the cleanup methods are called.
 *
 * For the longest time the ipv4 icmp code was registered as a pernet
 * device which caused kernel oops, and panics during network
 * namespace cleanup.   So please don't get this wrong.
 */
extern int register_pernet_subsys(struct pernet_operations *);
extern void unregister_pernet_subsys(struct pernet_operations *);
extern int register_pernet_gen_subsys(int *id, struct pernet_operations *);
extern void unregister_pernet_gen_subsys(int id, struct pernet_operations *);
extern int register_pernet_device(struct pernet_operations *);
extern void unregister_pernet_device(struct pernet_operations *);
extern int register_pernet_gen_device(int *id, struct pernet_operations *);
extern void unregister_pernet_gen_device(int id, struct pernet_operations *);

struct ctl_path;
struct ctl_table;
struct ctl_table_header;

extern struct ctl_table_header *register_net_sysctl_table(struct net *net,
	const struct ctl_path *path, struct ctl_table *table);
extern struct ctl_table_header *register_net_sysctl_rotable(
	const struct ctl_path *path, struct ctl_table *table);
extern void unregister_net_sysctl_table(struct ctl_table_header *header);

#endif /* __NET_NET_NAMESPACE_H */
