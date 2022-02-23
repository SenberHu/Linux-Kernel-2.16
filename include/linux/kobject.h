/*
 * kobject.h - generic kernel object infrastructure.
 *
 * Copyright (c) 2002-2003 Patrick Mochel
 * Copyright (c) 2002-2003 Open Source Development Labs
 * Copyright (c) 2006-2008 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2008 Novell Inc.
 *
 * This file is released under the GPLv2.
 *
 * Please read Documentation/kobject.txt before using the kobject
 * interface, ESPECIALLY the parts about reference counts and object
 * destructors.
 */

#ifndef _KOBJECT_H_
#define _KOBJECT_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <asm/atomic.h>

#define UEVENT_HELPER_PATH_LEN		256
#define UEVENT_NUM_ENVP			32	/* number of env pointers */
#define UEVENT_BUFFER_SIZE		2048	/* buffer for the variables */

/* path to the userspace helper executed on an event */
extern char uevent_helper[];

/* counter to tag the uevent, read only except for the kobject core */
extern u64 uevent_seqnum;

/*
 * The actions here must match the index to the string array
 * in lib/kobject_uevent.c
 *
 * Do not add new actions here without checking with the driver-core
 * maintainers. Action strings are not meant to express subsystem
 * or device specific properties. In most cases you want to send a
 * kobject_uevent_env(kobj, KOBJ_CHANGE, env) with additional event
 * specific variables added to the event environment.
 */
enum kobject_action {
	KOBJ_ADD, //向系统添加一个kset对象
	KOBJ_REMOVE, //内核对象被移除
	KOBJ_CHANGE, //内核对象发生变化
	KOBJ_MOVE,  //内核对象被移动
	KOBJ_ONLINE, //用于cpu 插入
	KOBJ_OFFLINE,//cpu移除
	KOBJ_MAX
};

/*kobject_init()初始化一个kobect对象

  kobject_add()  1: 建立kobect对象间的层次关系  2在sysfs文件系统中建立一个目录
  kobect_del()  在文件树中删除kobject
  
  kobject_init_and_add()  相当于上面两个函数的联合
  kobject_create() 创建并初始化一个kobect对象
  kobject_create_and_add() 创建 初始化 并添加到sysfs文件系统中
  
*/
struct kobject {
	const char		*name; //表示kobject对象的名字，对应sysfs下的一个目录
	                       //kobject_set_name()
	                       
	struct list_head	entry;  //将kobject连接到kset的连接件
	struct kobject		*parent;//是指向当前kobject父对象的指针，体现在sys结构中就是包含当前kobject对象的目录对象
	struct kset		*kset;      //若kobject已经连接到kset则用此指针指向他
	struct kobj_type	*ktype;//该内核对象一组sysfs文件系统相关的操作函数和属性
	struct sysfs_dirent	*sd;   //该内核对象在sysfs文件系统中对应的目录项实例
	struct kref		kref; //是对kobject的引用计数，当引用计数为0时，就回调之前注册的release方法释放该对象
	unsigned int state_initialized:1;// 1表示已经初始化  0表示未被初始化
	unsigned int state_in_sysfs:1;//表示已经在sysfs系统中建立一个入口点
	unsigned int state_add_uevent_sent:1;//添加事件是否发往用户空间
	unsigned int state_remove_uevent_sent:1;//删除事件是否发往用户空间
	unsigned int uevent_suppress:1;// 1表示在该对象状态发生变化时 不让所属kset往用户空间发送uevent消息
};

extern int kobject_set_name(struct kobject *kobj, const char *name, ...)
			    __attribute__((format(printf, 2, 3)));
extern int kobject_set_name_vargs(struct kobject *kobj, const char *fmt,
				  va_list vargs);

static inline const char *kobject_name(const struct kobject *kobj)
{
	return kobj->name;
}

extern void kobject_init(struct kobject *kobj, struct kobj_type *ktype);
extern int __must_check kobject_add(struct kobject *kobj,
				                           struct kobject *parent,
				                           const char *fmt, ...);
extern int __must_check kobject_init_and_add(struct kobject *kobj,
					     struct kobj_type *ktype,
					     struct kobject *parent,
					     const char *fmt, ...);

extern void kobject_del(struct kobject *kobj);

extern struct kobject * __must_check kobject_create(void);
extern struct kobject * __must_check kobject_create_and_add(const char *name,
						struct kobject *parent);

extern int __must_check kobject_rename(struct kobject *, const char *new_name);
extern int __must_check kobject_move(struct kobject *, struct kobject *);

extern struct kobject *kobject_get(struct kobject *kobj);
extern void kobject_put(struct kobject *kobj);

extern char *kobject_get_path(struct kobject *kobj, gfp_t flag);

//kobj_type的目标就是为不同类型的kobject提供不同的属性以及销毁方法
//get_ktype();
struct kobj_type 
{
	void (*release)(struct kobject *kobj);//在kobject_put()中会调用释放kobect对象
	struct sysfs_ops *sysfs_ops; //对attribute进行操作
	struct attribute **default_attrs;//每个属性代表一个此目录下的文件  
	                                 //比如在/sysfs/下加入了cat 这个kobject
	                                 //那么会有/sysfs/cat/ 这个目录  那么这个kobect有属性 size color
	                                 //那就会存在 /sysfs/cat/size  /sysfs/cat/color 这两个文件
};

//Uevent事件具体以环境变量（即字符串）的形式发送到用户空间
struct kobj_uevent_env {
	char *envp[UEVENT_NUM_ENVP]; /*环境变量指针数组  指向下面的buf  将buf进行分段 每段表示一个key=value字符串以\0结尾*/
	int envp_idx; /*数组下标*/
	char buf[UEVENT_BUFFER_SIZE]; //环境变量buffer
	int buflen;//buf中数据长度
};

struct kset_uevent_ops 
{
	//过滤回调函数 返回0 表示不需要向用户空间报告该事件
	int (*filter)(struct kset *kset, struct kobject *kobj);

    //名字回调函数 返回子系统名字 即环境变量SUBSYSTEM的名称
	const char *(*name)(struct kset *kset, struct kobject *kobj);

    //添加子系统特定的环境变量
	int (*uevent)(struct kset *kset, struct kobject *kobj,struct kobj_uevent_env *env);
};

struct kobj_attribute 
{
	struct attribute attr;

	//读取属性的内容
	ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf);

	//存取属性的内容
	ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count);
};

extern struct sysfs_ops kobj_sysfs_ops;

/**
 * struct kset - a set of kobjects of a specific type, belonging to a specific subsystem.
 *
 * A kset defines a group of kobjects.  They can be individually
 * different "types" but overall these kobjects all want to be grouped
 * together and operated on in the same manner.  ksets are used to
 * define the attribute callbacks and other common events that happen to
 * a kobject.
 *
 * @list: the list of all kobjects for this kset
 * @list_lock: a lock for iterating over the kobjects
 * @kobj: the embedded kobject for this kset (recursion, isn't it fun...)
 * @uevent_ops: the set of uevent operations for this kset.  These are
 * called whenever a kobject has something happen to it so that the kset
 * can add new environment variables, or filter out the uevents if so
 * desired.
 */
 //一组kobject的集合
 /*
kset_init();
kset_add();
kset_register();
kset_unregister();
kset_get()
kset_put();
*/
struct kset {
	struct list_head list;//这个kset的所有kobject的链表
	spinlock_t list_lock;//遍历list时候的自旋锁
	struct kobject kobj;//代表当前kset的kobj内核对象
	struct kset_uevent_ops *uevent_ops; //一组函数指针 当kset中的kobject发生状态变化需要通知用户空间 调用其中的函数来实现
};

//初始化一个kset对象
extern void kset_init(struct kset *kset);

//用来初始化并注册一个kset对象
extern int __must_check kset_register(struct kset *kset);

//注销一个kset对象
extern void kset_unregister(struct kset *kset);

//动态产生一个kset并将其加入sysfs系统中
//name:为kset名字
//u:kset对象用来处理用户空间event消息的操作集
//parent_kobj:父内核对象指针
extern struct kset * __must_check kset_create_and_add(const char *name,
						struct kset_uevent_ops *u,
						struct kobject *parent_kobj);

static inline struct kset *to_kset(struct kobject *kobj)
{
	return kobj ? container_of(kobj, struct kset, kobj) : NULL;
}

static inline struct kset *kset_get(struct kset *k)
{
	return k ? to_kset(kobject_get(&k->kobj)) : NULL;
}

static inline void kset_put(struct kset *k)
{
	kobject_put(&k->kobj);
}

static inline struct kobj_type *get_ktype(struct kobject *kobj)
{
	return kobj->ktype;
}

extern struct kobject *kset_find_obj(struct kset *, const char *);

/* The global /sys/kernel/ kobject for people to chain off of */
extern struct kobject *kernel_kobj;
/* The global /sys/kernel/mm/ kobject for people to chain off of */
extern struct kobject *mm_kobj;
/* The global /sys/hypervisor/ kobject for people to chain off of */
extern struct kobject *hypervisor_kobj;
/* The global /sys/power/ kobject for people to chain off of */
extern struct kobject *power_kobj;
/* The global /sys/firmware/ kobject for people to chain off of */
extern struct kobject *firmware_kobj;

#if defined(CONFIG_HOTPLUG)
int kobject_uevent(struct kobject *kobj, enum kobject_action action);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
			char *envp[]);

int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...)
	__attribute__((format (printf, 2, 3)));

int kobject_action_type(const char *buf, size_t count,
			enum kobject_action *type);
#else
static inline int kobject_uevent(struct kobject *kobj,
				 enum kobject_action action)
{ return 0; }
static inline int kobject_uevent_env(struct kobject *kobj,
				      enum kobject_action action,
				      char *envp[])
{ return 0; }

static inline int add_uevent_var(struct kobj_uevent_env *env,
				 const char *format, ...)
{ return 0; }

static inline int kobject_action_type(const char *buf, size_t count,
				      enum kobject_action *type)
{ return -EINVAL; }
#endif

#endif /* _KOBJECT_H_ */
