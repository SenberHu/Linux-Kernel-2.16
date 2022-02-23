#ifndef __ASM_GENERIC_SOCKET_H
#define __ASM_GENERIC_SOCKET_H

#include <asm/sockios.h>

/* For setsockopt(2) */
#define SOL_SOCKET	1

#define SO_DEBUG	1      //仅用于TCP 保留该套接字发送接收的所有分组详细跟踪信息 用dmesg程序进程检查 (int)

#define SO_REUSEADDR	2  //允许重用本地地址 (int) 

#define SO_TYPE		3  //获得套接字类型 (int)  SOCK_STREAM 
#define SO_ERROR	4
#define SO_DONTROUTE	5  //绕过外出路由表查询 (int)
#define SO_BROADCAST	6  //开启或禁止进程发送广播 (int)   对UDP

//对于客户SO_RCVBUF必须在connect之前调用,对于服务器 SO_RCVBUF需要在listen()之前设置	
#define SO_SNDBUF	7      //设置发送缓冲区(int)
#define SO_RCVBUF	8	   //设置接收缓冲区(int) 至少是MSS的4倍 依据TCP快速恢复算法的工作机制

#define SO_SNDBUFFORCE	32
#define SO_RCVBUFFORCE	33

#define SO_KEEPALIVE	9  //两个小时内该套接字任何一方都没有数据交换 tcp会自动给对端发送一个"保持存活探测分节" (int)
						   //时间设置 /proc/sys/net/ipv4/tcp_keepalive_time 
			               /*
								1) 对端发送一个ack
								2) 对端发送一个RST 表示进程崩溃
								3) 无响应  则本端继续发探测分节 若发出第一个探测后11多分还没反应 则放弃发送
							*/			
#define SO_OOBINLINE	10 //让接收到的带外数据留在正常的输入队列中 (int)

#define SO_NO_CHECK	11
#define SO_PRIORITY	12

#define SO_LINGER	13  //struct linger
                       /* 本选项指定close面对连接如何操作 默认close立即返回,但若有数据存在发送缓冲区 则先将数据进行发送*/

#define SO_BSDCOMPAT	14
/* To add :#define SO_REUSEPORT 15 */

#ifndef SO_PASSCRED /* powerpc only differs in these */
#define SO_PASSCRED	16
#define SO_PEERCRED	17

//下面两个标记由select使用 看(接收或发送)数据的个数是否可以让select返回
#define SO_RCVLOWAT	18   //接收低水位标记 (int)  默认值为1
#define SO_SNDLOWAT	19   //发送低水位标记 (int)  默认值为1


						
#define SO_RCVTIMEO	20   //接收超时(timeval{})
#define SO_SNDTIMEO	21   //发送超时(timeval{})
#endif

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION		22
#define SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define SO_SECURITY_ENCRYPTION_NETWORK		24

#define SO_BINDTODEVICE	25

/* Socket filtering */
#define SO_ATTACH_FILTER	26
#define SO_DETACH_FILTER	27

#define SO_PEERNAME		28
#define SO_TIMESTAMP		29
#define SCM_TIMESTAMP		SO_TIMESTAMP

#define SO_ACCEPTCONN		30

#define SO_PEERSEC		31
#define SO_PASSSEC		34
#define SO_TIMESTAMPNS		35
#define SCM_TIMESTAMPNS		SO_TIMESTAMPNS

#define SO_MARK			36

#define SO_TIMESTAMPING		37
#define SCM_TIMESTAMPING	SO_TIMESTAMPING

#define SO_PROTOCOL		38
#define SO_DOMAIN		39

#endif /* __ASM_GENERIC_SOCKET_H */
