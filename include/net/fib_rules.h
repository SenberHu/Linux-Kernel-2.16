#ifndef __NET_FIB_RULES_H
#define __NET_FIB_RULES_H

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/fib_rules.h>
#include <net/flow.h>
#include <net/rtnetlink.h>

//策略规则对应的数据结构
//对于ipv4其为fib4_rule
struct fib_rule
{
	struct list_head	list; // 用来链入路由规则函数队列中(fib_rules_ops,下面介绍)  
	atomic_t		refcnt;   // 计数器 
	int			ifindex;      // 网络设备接口索引
	char			ifname[IFNAMSIZ];// 设备名称 
	u32			mark;         // 用于过滤作用
	u32			mark_mask;    // 掩码 
	u32			pref;         // 优先级(例如上面代码中分别是0,0x7FEE，0x7FFF) 
	u32			flags;        // 标识位 
	u32			table;        // 路由函数表id(例如本地LOCAL，主路由MAIN...)  

	u8			action;       // 动作，即怎么去处理这个数据包 FR_ACT_TO_TBL  
	                          //即匹配后的规则，即会进入到相应的路由表，继续进行路由项的匹配  
	u32			target;
	struct fib_rule *	ctarget;// 当前规则
	struct rcu_head		rcu;
	struct net *		fr_net; // 网络空间结构指针 
};

struct fib_lookup_arg
{
	void			*lookup_ptr;
	void			*result;
	struct fib_rule		*rule;
};

struct fib_rules_ops
{
	int			family; // 协议族ID  
	struct list_head	list; /*主要是将注册到系统的fib_rules_ops链接到链表rules_ops中*/
	int			rule_size;  /*一个策略规则所占用的内存大小*/
	int			addr_size;  /*协议相关的地址的长度*/
	int			unresolved_rules;
	int			nr_goto_rules;

    /*协议相关的action函数，即是策略规则匹配后，所调用的action函数，执行后续的操作，
    一般是获取到相应的路由表，查找符合要求的路由项*/
	int			(*action)(struct fib_rule *,
					  struct flowi *, int,
					  struct fib_lookup_arg *);
	
    /*协议相关的规则匹配函数，对于策略规则的匹配，首先是通用匹配，
    待通用匹配完成后，则会调用该函数，进行协议相关参数（源、目的地址等）的匹配*/  	
	int			(*match)(struct fib_rule *,
					 struct flowi *, int);

	/*协议相关的配置函数*/
	int			(*configure)(struct fib_rule *,
					     struct sk_buff *,
					     struct fib_rule_hdr *,
					     struct nlattr **);
	
	int			(*compare)(struct fib_rule *,
					   struct fib_rule_hdr *,
					   struct nlattr **);// 对比函数指针 
	int			(*fill)(struct fib_rule *, struct sk_buff *,
					struct fib_rule_hdr *); // 填写函数指针  
	u32			(*default_pref)(struct fib_rules_ops *ops);// 查找优先级函数指针
	size_t			(*nlmsg_payload)(struct fib_rule *);// 统计负载数据能力函数指针 

	/* Called after modifications to the rules set, must flush
	 * the route cache if one exists. */
	void			(*flush_cache)(struct fib_rules_ops *ops); // 修改规则之后刷新缓存函数指针

	int			nlgroup; // 路由netlink组划分标识
	const struct nla_policy	*policy; // netlink属性优先级 
	struct list_head	rules_list;  // 路由规则队列 
	struct module		*owner;
	struct net		*fro_net;// 网络空间结构指针
};

#define FRA_GENERIC_POLICY \
	[FRA_IFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_PRIORITY]	= { .type = NLA_U32 }, \
	[FRA_FWMARK]	= { .type = NLA_U32 }, \
	[FRA_FWMASK]	= { .type = NLA_U32 }, \
	[FRA_TABLE]     = { .type = NLA_U32 }, \
	[FRA_GOTO]	= { .type = NLA_U32 }

static inline void fib_rule_get(struct fib_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static inline void fib_rule_put_rcu(struct rcu_head *head)
{
	struct fib_rule *rule = container_of(head, struct fib_rule, rcu);
	release_net(rule->fr_net);
	kfree(rule);
}

static inline void fib_rule_put(struct fib_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt))
		call_rcu(&rule->rcu, fib_rule_put_rcu);
}

static inline u32 frh_get_table(struct fib_rule_hdr *frh, struct nlattr **nla)
{
	if (nla[FRA_TABLE])
		return nla_get_u32(nla[FRA_TABLE]);
	return frh->table;
}

extern int fib_rules_register(struct fib_rules_ops *);
extern void fib_rules_unregister(struct fib_rules_ops *);
extern void fib_rules_cleanup_ops(struct fib_rules_ops *);

extern int	fib_rules_lookup(struct fib_rules_ops *,
						               struct flowi *, int flags,
						               struct fib_lookup_arg *);
extern int  fib_default_rule_add(struct fib_rules_ops *,
						                     u32 pref, u32 table,
						                     u32 flags);
#endif
