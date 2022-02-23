#ifndef _LINUX_CDEV_H
#define _LINUX_CDEV_H

#include <linux/kobject.h>
#include <linux/kdev_t.h>
#include <linux/list.h>

struct file_operations;
struct inode;
struct module;

/*
（1）MKDEV(主设备号，此设备号)
（2）MAJOR(dev_t dev)
（3）MINOR(dev_t dev)

  alloc_chrdev_region() 动态分配主设备号
  unregister_chrdev_region() 注销设备号

  class_create();用于在/dev/xx下创建节点
  class_destroy();
  device_create()
  device_destroy();
  
*/

struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops; //设备操作函数集
	struct list_head list;
	dev_t dev; //设备号
	unsigned int count; //设备数
};

//初始化一个字符设备描述符cdev{}
void cdev_init(struct cdev *, const struct file_operations *);


struct cdev *cdev_alloc(void);

void cdev_put(struct cdev *p);


//注册一个字符设备
int cdev_add(struct cdev *, dev_t, unsigned);

//注销一个字符设备
void cdev_del(struct cdev *);

int cdev_index(struct inode *inode);

void cd_forget(struct inode *);

extern struct backing_dev_info directly_mappable_cdev_bdi;

#endif
