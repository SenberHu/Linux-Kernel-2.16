#ifndef _LINUX_BINFMTS_H
#define _LINUX_BINFMTS_H

#include <linux/capability.h>

struct pt_regs;

/*
 * These are the maximum length and maximum number of strings passed to the
 * execve() system call.  MAX_ARG_STRLEN is essentially random but serves to
 * prevent the kernel from being unduly impacted by misaddressed pointers.
 * MAX_ARG_STRINGS is chosen to fit in a signed 32-bit integer.
 */
#define MAX_ARG_STRLEN (PAGE_SIZE * 32)
#define MAX_ARG_STRINGS 0x7FFFFFFF

/* sizeof(linux_binprm->buf) */
#define BINPRM_BUF_SIZE 128

#ifdef __KERNEL__
#include <linux/list.h>

#define CORENAME_MAX_SIZE 128

/*
 * This structure is used to hold the arguments that are used when loading binaries.
 */
struct linux_binprm{
	char buf[BINPRM_BUF_SIZE];//保存可执行文件的头128字节
#ifdef CONFIG_MMU
	struct vm_area_struct *vma;
#else
# define MAX_ARG_PAGES	32
	struct page *page[MAX_ARG_PAGES];
#endif
	struct mm_struct *mm;
	unsigned long p; /* current top of mem 当前内存最高地址*/
	unsigned int
		cred_prepared:1,/* true if creds already prepared (multiple
				 * preps happen for interpreters) */
		cap_effective:1;/* true if has elevated effective capabilities,
				 * false if not; except for init which inherits
				 * its parent's caps anyway */
#ifdef __alpha__
	unsigned int taso:1;
#endif
	unsigned int recursion_depth;
	struct file * file;//要执行的文件
	struct cred *cred;	/* new credentials */
	int unsafe;		/* how unsafe this exec is (mask of LSM_UNSAFE_*) */
	unsigned int per_clear;	/* bits to clear in current->personality */
	int argc, envc;//命令行参数和环境变量数目
	char * filename;	/* Name of binary as seen by procps 要执行的文件的名称(一个全路径) */
	char * interp;		/* Name of the binary really executed. Most
				   of the time same as filename, but could be
				   different for binfmt_{misc,script} 要执行的文件的真实名称，通常和filename相同*/
	unsigned interp_flags;
	unsigned interp_data;
	unsigned long loader, exec;
};

#define BINPRM_FLAGS_ENFORCE_NONDUMP_BIT 0
#define BINPRM_FLAGS_ENFORCE_NONDUMP (1 << BINPRM_FLAGS_ENFORCE_NONDUMP_BIT)

/* fd of the binary should be passed to the interpreter */
#define BINPRM_FLAGS_EXECFD_BIT 1
#define BINPRM_FLAGS_EXECFD (1 << BINPRM_FLAGS_EXECFD_BIT)

#define BINPRM_MAX_RECURSION 4

/*
 * This structure defines the functions that are used to load the binary formats that
 * linux accepts.
 */
struct linux_binfmt {
	struct list_head lh;
	struct module *module;
	int (*load_binary)(struct linux_binprm *, struct  pt_regs * regs);//通过读存放在可执行文件中的信息为当前进程建立一个新的执行环境
	int (*load_shlib)(struct file *);//用于动态的把一个共享库捆绑到一个已经在运行的进程, 这是由uselib()系统调用激活的
	 // 将当前进程的上下文保存在一个名为core的文件中

	//在名为core的文件中, 存放当前进程的执行上下文. 这个文件通常是在进程接收到一个缺省操作为”dump”的信号时被创建的, 其格式取决于被执行程序的可执行类型 
	int (*core_dump)(long signr, struct pt_regs *regs, struct file *file, unsigned long limit);
	unsigned long min_coredump;	/* minimal dump size */
	int hasvdso;
};

extern int __register_binfmt(struct linux_binfmt *fmt, int insert);

/* Registration of default binfmt handlers */
static inline int register_binfmt(struct linux_binfmt *fmt)
{
	return __register_binfmt(fmt, 0);
}

//添加和删除linux_binfmt结构体链表中的元素，以支持用户特定的可执行文件类型
/* Same as above, but adds a new binfmt at the top of the list */
static inline int insert_binfmt(struct linux_binfmt *fmt)
{
	return __register_binfmt(fmt, 1);
}

extern void unregister_binfmt(struct linux_binfmt *);

extern int prepare_binprm(struct linux_binprm *);
extern int __must_check remove_arg_zero(struct linux_binprm *);
extern int search_binary_handler(struct linux_binprm *,struct pt_regs *);
extern int flush_old_exec(struct linux_binprm * bprm);
extern void setup_new_exec(struct linux_binprm * bprm);

extern int suid_dumpable;
#define SUID_DUMP_DISABLE	0	/* No setuid dumping */
#define SUID_DUMP_USER		1	/* Dump as user of process */
#define SUID_DUMP_ROOT		2	/* Dump as root */

/* Stack area protections */
#define EXSTACK_DEFAULT   0	/* Whatever the arch defaults to */

//堆栈没有可执行权限
#define EXSTACK_DISABLE_X 1	/* Disable executable stacks */

//堆栈有可执行权限
#define EXSTACK_ENABLE_X  2	/* Enable executable stacks */

extern int setup_arg_pages(struct linux_binprm * bprm,
			   unsigned long stack_top,
			   int executable_stack);
extern int bprm_mm_init(struct linux_binprm *bprm);
extern int copy_strings_kernel(int argc,char ** argv,struct linux_binprm *bprm);
extern int prepare_bprm_creds(struct linux_binprm *bprm);
extern void install_exec_creds(struct linux_binprm *bprm);
extern void do_coredump(long signr, int exit_code, struct pt_regs *regs);
extern void set_binfmt(struct linux_binfmt *new);
extern void free_bprm(struct linux_binprm *);

#endif /* __KERNEL__ */
#endif /* _LINUX_BINFMTS_H */
