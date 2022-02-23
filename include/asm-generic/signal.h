#ifndef __ASM_GENERIC_SIGNAL_H
#define __ASM_GENERIC_SIGNAL_H

#include <linux/types.h>

#define _NSIG		64
#define _NSIG_BPW	__BITS_PER_LONG
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

#define SIGHUP		 1 //挂断控制终端或进程
#define SIGINT		 2//来自键盘的中断
#define SIGQUIT		 3 //来自键盘的退出
#define SIGILL		 4//非法指令
#define SIGTRAP		 5//跟踪断点
#define SIGABRT		 6//异常结束
#define SIGIOT		 6//等价SIGABRT
#define SIGBUS		 7//z总线错误
#define SIGFPE		 8//浮点异常
#define SIGKILL		 9//强制终止进程
#define SIGUSR1		10//进程可以使用
#define SIGSEGV		11 //进程引用一个无效的页
#define SIGUSR2		12//
#define SIGPIPE		13//向无读者的管道写
#define SIGALRM		14//定时器时钟
#define SIGTERM		15//进程终止
#define SIGSTKFLT	16//协处理器栈错误
#define SIGCHLD		17 //当某一个子进程停止或终止的时候 发送给父进程
#define SIGCONT		18//如果停止则回复执行
#define SIGSTOP		19//停止进程执行
#define SIGTSTP		20//从tty发出停止进程
#define SIGTTIN		21//后台进程请求输入
#define SIGTTOU		22//后台进程请求输出
#define SIGURG		23//套接字紧急指针
#define SIGXCPU		24//超过CPU时限
#define SIGXFSZ		25//超过文件大小限制
#define SIGVTALRM	26//虚拟定时器时钟
#define SIGPROF		27//概况定机器时钟
#define SIGWINCH	28//窗口调整大小
#define SIGIO		29//IO现在可能发生
#define SIGPOLL		SIGIO
/*
#define SIGLOST		29
*/
#define SIGPWR		30//电源供给失效
#define SIGSYS		31
#define	SIGUNUSED	31//没有使用

/* These should not be considered constants from userland.  */
#define SIGRTMIN	32
#ifndef SIGRTMAX
#define SIGRTMAX	_NSIG
#endif

/*
 * SA_FLAGS values:
 *
 * SA_ONSTACK indicates that a registered stack_t will be used.
 * SA_RESTART flag to get restarting signals (which were the default long ago)
 * SA_NOCLDSTOP flag to turn off SIGCHLD when children stop.
 * SA_RESETHAND clears the handler when the signal is delivered.
 * SA_NOCLDWAIT flag on SIGCHLD to inhibit zombies.
 * SA_NODEFER prevents the current signal from being masked in the handler.
 *
 * SA_ONESHOT and SA_NOMASK are the historical Linux names for the Single
 * Unix names RESETHAND and NODEFER respectively.
 */
#define SA_NOCLDSTOP	0x00000001//当该位设置时，在子进程stop时不产生SIGCHLD信号
#define SA_NOCLDWAIT	0x00000002
#define SA_SIGINFO	0x00000004
#define SA_ONSTACK	0x08000000//表明要使用已经注册的新栈，而不是使用进程自身的栈
#define SA_RESTART	0x10000000//设置在信号被中断后重启
#define SA_NODEFER	0x40000000//一般情况下， 当信号处理函数运行时，内核将阻塞该给定信号。但是如果设置了 SA_NODEFER标记， 那么在该信号处理函数运行时，内核将不会阻塞该信号
#define SA_RESETHAND	0x80000000//当调用信号处理函数时，将信号的处理函数重置为缺省值SIG_DFL

#define SA_NOMASK	SA_NODEFER
#define SA_ONESHOT	SA_RESETHAND

/*
 * New architectures should not define the obsolete
 *	SA_RESTORER	0x04000000
 */

/*
 * sigaltstack controls
 */
#define SS_ONSTACK	1
#define SS_DISABLE	2

#define MINSIGSTKSZ	2048
#define SIGSTKSZ	8192

#ifndef __ASSEMBLY__
typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

/* not actually used, but required for linux/syscalls.h */
typedef unsigned long old_sigset_t;

#include <asm-generic/signal-defs.h>

struct sigaction {
	__sighandler_t sa_handler;//sa_handler指向一个处理函数
	unsigned long sa_flags;//记录信号处理时的一些设置 如:SA_RESTART：设置在信号被中断后重启
#ifdef SA_RESTORER
	__sigrestore_t sa_restorer;
#endif
	sigset_t sa_mask;//sa_mask就代表在处理当前信号时，可以选择性的屏蔽一些信号。相当于即时有效的		/* mask last for extensibility */
};

struct k_sigaction {
	struct sigaction sa;
};

typedef struct sigaltstack {
	void __user *ss_sp;
	int ss_flags;
	size_t ss_size;
} stack_t;

#ifdef __KERNEL__

#include <asm/sigcontext.h>
#undef __HAVE_ARCH_SIG_BITOPS

#define ptrace_signal_deliver(regs, cookie) do { } while (0)

#endif /* __KERNEL__ */
#endif /* __ASSEMBLY__ */

#endif /* _ASM_GENERIC_SIGNAL_H */
