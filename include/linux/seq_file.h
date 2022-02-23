#ifndef _LINUX_SEQ_FILE_H
#define _LINUX_SEQ_FILE_H

#include <linux/types.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/cpumask.h>
#include <linux/nodemask.h>

struct seq_operations;
struct file;
struct path;
struct inode;
struct dentry;

/*
描述了seq处理的缓冲区及处理方法，buf是动态分配的，
大小不小于PAGE_SIZE，通常这个结构是通过struct file结构中的private_data来指向的
*/
struct seq_file {
	char *buf;//seq流的缓冲区
	size_t size;//缓冲区大小
	size_t from;//表示从缓冲区开始传的位置为偏移量 
	size_t count;//缓冲区中存在的数据的长度
	loff_t index;//数据记录索引值
	loff_t read_pos;
	u64 version;//版本号，是struct file的版本号的拷贝
	struct mutex lock;//seq锁
	const struct seq_operations *op;//seq操作结构，定义数据显示的操作函数
	void *private;//私有数据
};

struct seq_operations {
	/*是一个整型位置值，指示开始读取的位置。对于这个位置的意义完全取决于底层实现，不一定是字节为单位的位置，可能是一个元素的序列号*/
	void * (*start) (struct seq_file *m, loff_t *pos);//start 方法会首先被调用，它的作用是在设置访问的起始点

	
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};

#define SEQ_SKIP 1

/**
 * seq_get_buf - get buffer to write arbitrary data to
 * @m: the seq_file handle
 * @bufp: the beginning of the buffer is stored here
 *
 * Return the number of bytes available in the buffer, or zero if
 * there's no space.
 */
static inline size_t seq_get_buf(struct seq_file *m, char **bufp)
{
	BUG_ON(m->count > m->size);
	if (m->count < m->size)
		*bufp = m->buf + m->count;
	else
		*bufp = NULL;

	return m->size - m->count;
}

/**
 * seq_commit - commit data to the buffer
 * @m: the seq_file handle
 * @num: the number of bytes to commit
 *
 * Commit @num bytes of data written to a buffer previously acquired
 * by seq_buf_get.  To signal an error condition, or that the data
 * didn't fit in the available space, pass a negative @num value.
 */
static inline void seq_commit(struct seq_file *m, int num)
{
	if (num < 0) {
		m->count = m->size;
	} else {
		BUG_ON(m->count + num > m->size);
		m->count += num;
	}
}

char *mangle_path(char *s, char *p, char *esc);
int seq_open(struct file *, const struct seq_operations *);
ssize_t seq_read(struct file *, char __user *, size_t, loff_t *);
loff_t seq_lseek(struct file *, loff_t, int);
int seq_release(struct inode *, struct file *);
int seq_escape(struct seq_file *, const char *, const char *);
int seq_putc(struct seq_file *m, char c);
int seq_puts(struct seq_file *m, const char *s);
int seq_write(struct seq_file *seq, const void *data, size_t len);

int seq_printf(struct seq_file *, const char *, ...)
	__attribute__ ((format (printf,2,3)));

int seq_path(struct seq_file *, struct path *, char *);
int seq_dentry(struct seq_file *, struct dentry *, char *);
int seq_path_root(struct seq_file *m, struct path *path, struct path *root,
		  char *esc);
int seq_bitmap(struct seq_file *m, const unsigned long *bits,
				   unsigned int nr_bits);
static inline int seq_cpumask(struct seq_file *m, const struct cpumask *mask)
{
	return seq_bitmap(m, cpumask_bits(mask), nr_cpu_ids);
}

static inline int seq_nodemask(struct seq_file *m, nodemask_t *mask)
{
	return seq_bitmap(m, mask->bits, MAX_NUMNODES);
}

int seq_bitmap_list(struct seq_file *m, const unsigned long *bits,
		unsigned int nr_bits);

static inline int seq_cpumask_list(struct seq_file *m,
				   const struct cpumask *mask)
{
	return seq_bitmap_list(m, cpumask_bits(mask), nr_cpu_ids);
}

static inline int seq_nodemask_list(struct seq_file *m, nodemask_t *mask)
{
	return seq_bitmap_list(m, mask->bits, MAX_NUMNODES);
}

int single_open(struct file *, int (*)(struct seq_file *, void *), void *);
int single_release(struct inode *, struct file *);
void *__seq_open_private(struct file *, const struct seq_operations *, int);
int seq_open_private(struct file *, const struct seq_operations *, int);
int seq_release_private(struct inode *, struct file *);

#define SEQ_START_TOKEN ((void *)1)

/*
 * Helpers for iteration over list_head-s in seq_files
 */

extern struct list_head *seq_list_start(struct list_head *head,
		loff_t pos);
extern struct list_head *seq_list_start_head(struct list_head *head,
		loff_t pos);
extern struct list_head *seq_list_next(void *v, struct list_head *head,
		loff_t *ppos);

#endif
