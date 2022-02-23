#ifndef _LINUX_STAT_H
#define _LINUX_STAT_H

#ifdef __KERNEL__

#include <asm/stat.h>

#endif

#if defined(__KERNEL__) || !defined(__GLIBC__) || (__GLIBC__ < 2)

#define S_IFMT  00170000
#define S_IFSOCK 0140000 //socket
#define S_IFLNK	 0120000 //符号连接
#define S_IFREG  0100000 //普通文件
#define S_IFBLK  0060000 //块设备
#define S_IFDIR  0040000 //目录
#define S_IFCHR  0020000 //字符设备
#define S_IFIFO  0010000 //FIFO
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700 //READ WRITE 执行  USER
#define S_IRUSR 00400 //READ USER
#define S_IWUSR 00200 //WRITE USER
#define S_IXUSR 00100 //执行 USER

#define S_IRWXG 00070 //READ WRITE 执行 GROUP
#define S_IRGRP 00040 //READ GROUP
#define S_IWGRP 00020 //WRITE GROUP
#define S_IXGRP 00010 //执行 GROUP

#define S_IRWXO 00007 //READ WRITE 执行 OTHER
#define S_IROTH 00004 //READ OTHER
#define S_IWOTH 00002 //WRITE OTHER
#define S_IXOTH 00001 //执行 OTHER

#endif

#ifdef __KERNEL__
#define S_IRWXUGO	(S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
#define S_IRUGO		(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO		(S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO		(S_IXUSR|S_IXGRP|S_IXOTH)

#define UTIME_NOW	((1l << 30) - 1l)
#define UTIME_OMIT	((1l << 30) - 2l)

#include <linux/types.h>
#include <linux/time.h>

struct kstat {
	u64		ino;
	dev_t		dev;
	umode_t		mode;
	unsigned int	nlink;
	uid_t		uid;
	gid_t		gid;
	dev_t		rdev;
	loff_t		size;
	struct timespec  atime;
	struct timespec	mtime;
	struct timespec	ctime;
	unsigned long	blksize;
	unsigned long long	blocks;
};

#endif

#endif
