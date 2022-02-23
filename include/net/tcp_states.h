/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol sk_state field.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_STATES_H
#define _LINUX_TCP_STATES_H

//tcp连接状态
//下面中A端为关闭的发起端即首个发送FIN报文的一端
enum {
	TCP_ESTABLISHED = 1,//客户端接收到之前发送的SYN的ACK后 设置此状态,并紧接着发送一个ACK给服务端,而此时SYN_RECV状态的服务端收到此ACK后也将进入此状态
	TCP_SYN_SENT, //客户端发送一个SYN报文请求建立与服务的连接后 设置该状态,仅仅表示发送的SYN 但尚未得到应答 若得到应答进入TCP_ESTABLISHED
	TCP_SYN_RECV,//服务端在接收到客户端发送的SYN 会发送一个附带ACK的SYN报文给客户端,之后设置此状态
	TCP_FIN_WAIT1,//A端发起关闭操作,A端将发送一个FIN给对方 并将状态设置为TCP_FIN_WAIT1
	TCP_FIN_WAIT2,//处于TCP_FIN_WAIT1状态的A端在在接收到之前发送的FIN的ACK报文后将其状态设置为TCP_FIN_WAIT2,然后一直处于此状态,直到接收到对方发送的FIN
                  //在接收到对方的FIN之前 此端一直可以进行报文的接收,A端发送FIN仅仅表示 A端不会再发送报文,但还可以接收报文
                  
	TCP_TIME_WAIT,//TCP_FIN_WAIT2状态的A端在接收到对方的FIN后进入TCP_TIME_WAIT状态表示静等待2MSL
	TCP_CLOSE,     //关闭状态,在三次握手机制建立前处于此状态
	TCP_CLOSE_WAIT,//B端在接收到A端的FIN报文时,将本地状态设置为此状态 ,并发送ACK给A端,此后B端仍然可以发送没有发送完的数据给A端
	TCP_LAST_ACK,//B端在发送FIN给A端后则状态设置为LAST_ACK等待A端的ACK报文，一旦接受到ACK则关闭 B端进入CLOSED
	TCP_LISTEN, //监听状态，针对服务端  表示正在等待客户端连接请求
	TCP_CLOSING,	/* 当链接双方同时发送FIN报文会进入此状态(如同时执行close)*/

	TCP_MAX_STATES	/* Leave at the end! */
};

#define TCP_STATE_MASK	0xF

#define TCP_ACTION_FIN	(1 << 7)

enum {
	TCPF_ESTABLISHED = (1 << 1),
	TCPF_SYN_SENT	 = (1 << 2),
	TCPF_SYN_RECV	 = (1 << 3),
	TCPF_FIN_WAIT1	 = (1 << 4),
	TCPF_FIN_WAIT2	 = (1 << 5),
	TCPF_TIME_WAIT	 = (1 << 6),
	TCPF_CLOSE	 = (1 << 7),
	TCPF_CLOSE_WAIT	 = (1 << 8),
	TCPF_LAST_ACK	 = (1 << 9),
	TCPF_LISTEN	 = (1 << 10),
	TCPF_CLOSING	 = (1 << 11) 
};

#endif	/* _LINUX_TCP_STATES_H */
