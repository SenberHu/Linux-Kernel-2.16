/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Global definitions for the IP router interface.
 *
 * Version:	@(#)route.h	1.0.3	05/27/93
 *
 * Authors:	Original taken from Berkeley UNIX 4.3, (c) UCB 1986-1988
 *		for the purposes of compatibility only.
 *
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 * Changes:
 *              Mike McLagan    :       Routing by source
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_ROUTE_H
#define _LINUX_ROUTE_H

#include <linux/if.h>
#include <linux/compiler.h>

/* This structure gets passed by the SIOCADDRT and SIOCDELRT calls. */
struct rtentry 
{
	unsigned long	rt_pad1;
	struct sockaddr	rt_dst;		/* target address		*/
	struct sockaddr	rt_gateway;	/* gateway addr (RTF_GATEWAY)	*/
	struct sockaddr	rt_genmask;	/* target network mask (IP)	*/
	unsigned short	rt_flags;
	short		rt_pad2;
	unsigned long	rt_pad3;
	void		*rt_pad4;
	short		rt_metric;	/* +1 for binary compatibility!	*/
	char __user	*rt_dev;	/* forcing the device at add	*/
	unsigned long	rt_mtu;		/* per route MTU/Window 	*/
#ifndef __KERNEL__
#define rt_mss	rt_mtu			/* Compatibility :-(            */
#endif
	unsigned long	rt_window;	/* Window clamping 		*/
	unsigned short	rt_irtt;	/* Initial RTT			*/
};


#define	RTF_UP		0x0001		/* route usable	该表项可被使用	  	*/
#define	RTF_GATEWAY	0x0002		/* destination is a gateway	该表项通向一个路由器或网关*/
#define	RTF_HOST	0x0004		/* host entry (net otherwise)	该表项提供可直达目的主机的路径*/
#define RTF_REINSTATE	0x0008		/* reinstate route after tmout	该表项超市后已进行重新确认*/
#define	RTF_DYNAMIC	0x0010		/* created dyn. (by redirect)	该表项根据接收的数据包动态变化*/
#define	RTF_MODIFIED	0x0020		/* modified dyn. (by redirect)	该表项内容根据ICMP ReDire 信息进行了更改*/
#define RTF_MTU		0x0040		/* specific MTU for this route	*/
#define RTF_MSS		RTF_MTU		/* Compatibility :-(	最大传输单元 数据包大小满足该规定	*/
#define RTF_WINDOW	0x0080		/* per route window clamping	指定了窗口的大小*/
#define RTF_IRTT	0x0100		/* Initial round trip time	*/
#define RTF_REJECT	0x0200		/* Reject route			*/

/*
 *	<linux/ipv6_route.h> uses RTF values >= 64k
 */



#endif	/* _LINUX_ROUTE_H */

