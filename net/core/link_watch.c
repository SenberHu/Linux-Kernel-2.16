/*
 * Linux network device link state notification
 *
 * Author:
 *     Stefan Rompf <sux@loplof.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <net/sock.h>
#include <net/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/bitops.h>
#include <asm/types.h>


enum lw_bits {
	LW_URGENT = 0,
};

static unsigned long linkwatch_flags;//链路链接标志
static unsigned long linkwatch_nextevent;

static void linkwatch_event(struct work_struct *dummy);
static DECLARE_DELAYED_WORK(linkwatch_work, linkwatch_event);

static struct net_device *lweventlist;//包含未决的链路状态变更事件
static DEFINE_SPINLOCK(lweventlist_lock);

static unsigned char default_operstate(const struct net_device *dev)
{
	if (!netif_carrier_ok(dev))
		return (dev->ifindex != dev->iflink ?
			IF_OPER_LOWERLAYERDOWN : IF_OPER_DOWN);

	if (netif_dormant(dev))
		return IF_OPER_DORMANT;

	return IF_OPER_UP;
}


static void rfc2863_policy(struct net_device *dev)
{
	unsigned char operstate = default_operstate(dev);

	if (operstate == dev->operstate)
		return;

	write_lock_bh(&dev_base_lock);

	switch(dev->link_mode) {
	case IF_LINK_MODE_DORMANT:
		if (operstate == IF_OPER_UP)
			operstate = IF_OPER_DORMANT;
		break;

	case IF_LINK_MODE_DEFAULT:
	default:
		break;
	}

	dev->operstate = operstate;

	write_unlock_bh(&dev_base_lock);
}

/* 是否需要紧急处理的事件 */
static bool linkwatch_urgent_event(struct net_device *dev)
{
	return netif_running(dev) &&     /* 设备未运行，非紧急 */
		   netif_carrier_ok(dev) &&  //有载波信号 连接
		   qdisc_tx_changing(dev); //发送队列排队规则改变与否
}

/* 添加事件 */
static void linkwatch_add_event(struct net_device *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&lweventlist_lock, flags);
	//对于任何设备lweventlist列表都没有必要记录一个以上的实例 链路不是on 就是off没必要保存历史状态
	dev->link_watch_next = lweventlist;
	lweventlist = dev;
	spin_unlock_irqrestore(&lweventlist_lock, flags);
}

static void linkwatch_schedule_work(int urgent)
{
	unsigned long delay = linkwatch_nextevent - jiffies;

	 /* 已经设置了紧急标记，则返回 */
	if (test_bit(LW_URGENT, &linkwatch_flags))
		return;

	/* Minimise down-time: drop delay for up event. */
	 /* 需要紧急调度 */
	if (urgent) 
	{
	    /* 之前设置了，则返回 */
		if (test_and_set_bit(LW_URGENT, &linkwatch_flags))
			return;
		 /* 设置紧急，则立即执行 */
		delay = 0;
	}

	/* If we wrap around we'll delay it by at most HZ. */
	 /* 如果大于1s则立即执行 */
	if (delay > HZ)
		delay = 0;

	/*
	 * This is true if we've scheduled it immeditately or if we don't
	 * need an immediate execution and it's already pending.
	 */
	if (schedule_delayed_work(&linkwatch_work, delay) == !delay)
		return;

	/* Don't bother if there is nothing urgent. */
	/* 如果设置了紧急标记，则立即执行 */
	if (!test_bit(LW_URGENT, &linkwatch_flags))
		return;

	/* It's already running which is good enough. */
	if (!cancel_delayed_work(&linkwatch_work))
		return;

	/* Otherwise we reschedule it again for immediate exection. */
	schedule_delayed_work(&linkwatch_work, 0);
}

/*
@urgent_only--1-未到达下一次调度时间
              0-已到达下次调度时间
*/
static void __linkwatch_run_queue(int urgent_only)
{
	struct net_device *next;

	/*
	 * Limit the number of linkwatch events to one
	 * per second so that a runaway driver does not
	 * cause a storm of messages on the netlink
	 * socket.  This limit does not apply to up events
	 * while the device qdisc is down.
	 */
	  /* 已达到调度时间 */
	if (!urgent_only)
		linkwatch_nextevent = jiffies + HZ;
	
	/* Limit wrap-around effect on delay. */
     /*
         未到达调度时间，并且下一次调度在当前时间的1s以后 
         那么设置调度时间是当前时间
    */
	else if (time_after(linkwatch_nextevent, jiffies + HZ))
		linkwatch_nextevent = jiffies;
     /* 清除紧急标识 */
	clear_bit(LW_URGENT, &linkwatch_flags);

	spin_lock_irq(&lweventlist_lock);
	next = lweventlist;
	lweventlist = NULL;
	spin_unlock_irq(&lweventlist_lock);

	 /* 遍历链表 */
	while (next) 
	{   
	    /* 获取设备 */
		struct net_device *dev = next;
        
		next = dev->link_watch_next;

		if (urgent_only && !linkwatch_urgent_event(dev)) {
			linkwatch_add_event(dev);
			continue;
		}

		/*
		 * Make sure the above read is complete since it can be
		 * rewritten as soon as we clear the bit below.
		 */
		smp_mb__before_clear_bit();

		/* We are about to handle this device,
		 * so new events can be accepted
		 */
		 //清除未决标志
		clear_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state);

		rfc2863_policy(dev);
        //只有设备开启才会发送NETDEV_CHANGE消息  没人关心以关闭设备上链路的变更事件
		if (dev->flags & IFF_UP) 
		{
			if (netif_carrier_ok(dev))
				dev_activate(dev);
			else
				dev_deactivate(dev);
             //发送NETDEV_CHANGE消息
			netdev_state_change(dev);
		}

		dev_put(dev);
	}

	if (lweventlist)
		linkwatch_schedule_work(0);
}


/* Must be called with the rtnl semaphore held */
void linkwatch_run_queue(void)
{
	__linkwatch_run_queue(0);
}

//处理lweventlist列表上的链路变更事件
static void linkwatch_event(struct work_struct *dummy)
{
	rtnl_lock();
	__linkwatch_run_queue(time_after(linkwatch_nextevent, jiffies));
	rtnl_unlock();
}


void linkwatch_fire_event(struct net_device *dev)
{   
     /* 判断是否是紧急处理的事件 */
	bool urgent = linkwatch_urgent_event(dev);

	 /* 设置待处理事件标记 */
	if (!test_and_set_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state)) 
	{
		dev_hold(dev);
        /* 添加事件到事件列表 */
		linkwatch_add_event(dev);
	} 
	else if (!urgent)
		return;
	
    /* 事件调度 */
	linkwatch_schedule_work(urgent);
}

EXPORT_SYMBOL(linkwatch_fire_event);
