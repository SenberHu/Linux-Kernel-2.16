#ifndef _IPX_H_
#define _IPX_H_
#include <linux/types.h>
#include <linux/sockios.h>
#include <linux/socket.h>
#define IPX_NODE_LEN	6
#define IPX_MTU		576

//IPX协议接口地址定义 类似于sockaddr_in sockaddr_un
//此结构为16字节
struct sockaddr_ipx {
	sa_family_t	sipx_family; //AF_IPX
	__be16		sipx_port; //端口号
	__be32		sipx_network;//网络地址
	unsigned char 	sipx_node[IPX_NODE_LEN];//节点地址 一般为硬件地址
	__u8		sipx_type;
	unsigned char	sipx_zero;	/* 16 byte fill */
};

/*
 * So we can fit the extra info for SIOCSIFADDR into the address nicely
 */
#define sipx_special	sipx_port
#define sipx_action	sipx_zero
#define IPX_DLTITF	0
#define IPX_CRTITF	1

//设置ipx的路由表项，路由表项并非此结构表示而是ipx_route 
//ipx_route_definition用于创建一个ipx_route 这是一个信息传递中间结构体
struct ipx_route_definition {
	__be32        ipx_network;
	__be32        ipx_router_network;
	unsigned char ipx_router_node[IPX_NODE_LEN];
};


//设置或获取主机接口设备信息,在使用ipx同行的机器上每个网络接口都有一个ipx_interface 结构表示
struct ipx_interface_definition {
	__be32        ipx_network;
	unsigned char ipx_device[16];

//ipx链路层封装协议 取值如下常亮	
	unsigned char ipx_dlink_type;
#define IPX_FRAME_NONE		0

/*
------------------------------------------------------------------------------------
|发送硬件地址   | 接收硬件地址  | 长度   | IEEE802.2首部  | Code | 类型  | IPX报文 |
------------------------------------------------------------------------------------
*/
#define IPX_FRAME_SNAP		1 //ethnet SNAP


/*
------------------------------------------------------------------------
|发送硬件地址   | 接收硬件地址 | 长度  |DSAP | SSAP  | CTRL  | IPX报文 |
------------------------------------------------------------------------
*/
#define IPX_FRAME_8022		2 //IEEE802.2

/*
--------------------------------------------------
|发送硬件地址  | 接收硬件地址  | 类型  | ipx报文 |
--------------------------------------------------
*/
#define IPX_FRAME_ETHERII	3  //Eternet II

/*
---------------------------------------------------------
|发送端硬件地址  |  接收端硬件地址  | 长度   |  ipx报文 |
---------------------------------------------------------
*/
#define IPX_FRAME_8023		4  //802.3
#define IPX_FRAME_TR_8022       5 /* obsolete */
    
	unsigned char ipx_special;//该字段取值如下三个常量
#define IPX_SPECIAL_NONE	0
#define IPX_PRIMARY		1
#define IPX_INTERNAL		2
	unsigned char ipx_node[IPX_NODE_LEN];
};

struct ipx_config_data {
	unsigned char	ipxcfg_auto_select_primary;//用于设置内核变量ipxcfg_auto_select_primary
	unsigned char	ipxcfg_auto_create_interfaces;//用于设置内核变量ipxcfg_auto_create_interfaces
};

/*
 * OLD Route Definition for backward compatibility.
 */

//结构作用同ipx_route_definition  该结构为向后兼容保留的
struct ipx_route_def {
	__be32		ipx_network;
	__be32		ipx_router_network;
#define IPX_ROUTE_NO_ROUTER	0
	unsigned char	ipx_router_node[IPX_NODE_LEN];
	unsigned char	ipx_device[16];
	unsigned short	ipx_flags;
#define IPX_RT_SNAP		8
#define IPX_RT_8022		4
#define IPX_RT_BLUEBOOK		2
#define IPX_RT_ROUTED		1
};

//用于ipx_ioctrl 函数中相关信息设置或获取 
#define SIOCAIPXITFCRT		(SIOCPROTOPRIVATE)
#define SIOCAIPXPRISLT		(SIOCPROTOPRIVATE + 1)
#define SIOCIPXCFGDATA		(SIOCPROTOPRIVATE + 2)
#define SIOCIPXNCPCONN		(SIOCPROTOPRIVATE + 3)
#endif /* _IPX_H_ */
