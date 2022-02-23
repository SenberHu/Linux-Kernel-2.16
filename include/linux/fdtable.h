/*
 * descriptor table internals; you almost certainly want file.h instead.
 */

#ifndef __LINUX_FDTABLE_H
#define __LINUX_FDTABLE_H

#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/init.h>

#include <asm/atomic.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG

/*
 * The embedded_fd_set is a small fd_set,
 * suitable for most tasks (which open <= BITS_PER_LONG files)
 */
struct embedded_fd_set {
	unsigned long fds_bits[1];
};

struct fdtable {
	unsigned int max_fds;
	struct file ** fd;      /* current fd array */// 指向打开的文件描述符列表的指针，开始的时候指向fd_array
	fd_set *close_on_exec;// 执行exec需要关闭的文件描述符位图(fork，exec即不被子进程继承的文件描述符)
	fd_set *open_fds;//打开的文件描述符位图
	struct rcu_head rcu;
	struct fdtable *next;
};

/*
 * Open file table structure
 *///对于每个进程，包含一个files_struct结构，用来记录文件描述符的使用情况
struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count;//使用该表的进程数
	struct fdtable *fdt;
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	int next_fd; //数值最小的最近关闭文件的文件描述符,下一个可用的文件描述符
	struct embedded_fd_set close_on_exec_init;;// 执行exec时需要关闭的文件描述符初值集合
	struct embedded_fd_set open_fds_init;// 文件描述符的屏蔽字初值集合
	struct file * fd_array[NR_OPEN_DEFAULT];//默认打开的fd队列
};

#define files_fdtable(files) (rcu_dereference((files)->fdt))

struct file_operations;
struct vfsmount;
struct dentry;

extern int expand_files(struct files_struct *, int nr);
extern void free_fdtable_rcu(struct rcu_head *rcu);
extern void __init files_defer_init(void);

static inline void free_fdtable(struct fdtable *fdt)
{
	call_rcu(&fdt->rcu, free_fdtable_rcu);
}

static inline struct file * fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct file * file = NULL;
	struct fdtable *fdt = files_fdtable(files);

	if (fd < fdt->max_fds)
		file = rcu_dereference(fdt->fd[fd]);
	return file;
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

struct task_struct;

struct files_struct *get_files_struct(struct task_struct *);
void put_files_struct(struct files_struct *fs);
void reset_files_struct(struct files_struct *);
int unshare_files(struct files_struct **);
struct files_struct *dup_fd(struct files_struct *, int *);

extern struct kmem_cache *files_cachep;

#endif /* __LINUX_FDTABLE_H */
