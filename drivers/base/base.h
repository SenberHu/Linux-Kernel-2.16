
/**
 * struct bus_type_private - structure to hold the private to the driver core portions of the bus_type structure.
 *
 * @subsys - the struct kset that defines this bus.  This is the main kobject
 * @drivers_kset - the list of drivers associated with this bus
 * @devices_kset - the list of devices associated with this bus
 * @klist_devices - the klist to iterate over the @devices_kset
 * @klist_drivers - the klist to iterate over the @drivers_kset
 * @bus_notifier - the bus notifier list for anything that cares about things
 * on this bus.
 * @bus - pointer back to the struct bus_type that this structure is associated
 * with.
 *
 * This structure is the one that is the actual kobject allowing struct
 * bus_type to be statically allocated safely.  Nothing outside of the driver
 * core should ever touch these fields.
 */
struct bus_type_private {
	struct kset subsys;//该总线的内嵌kset 对应/sys/bus下的某个子目录 即/sys/bus/xxx/目录 其中xxx为总线名 例如pci
	
	struct kset *drivers_kset;//bus上所有驱动的一个集合  指向了该总线下的driver目录对应的指针  即/sys/bus/xxx/drivers
	struct kset *devices_kset;//bus上所有设备的一个集合  指向了该总线下的device目录对应的指针 即/sys/bus/xxx/device
	
	struct klist klist_devices;//这个总线类型的设备链表的表头
	struct klist klist_drivers;//这个总线类型的驱动链表的表头
	
	struct blocking_notifier_head bus_notifier;//总线类型变化通知链表的表头 调用bus_register_notifier或bus_unregister_notifier
	                                           //总线类型中添加设备/驱动 总线类型移除设备/驱动  驱动绑定/驱动松绑
	                                           
	unsigned int drivers_autoprobe:1; //是否支持设备自动探测设备 bus_add_driver()
	struct bus_type *bus; //指向属于的总线结构
};

struct driver_private {
	struct kobject kobj;
	struct klist klist_devices;
	struct klist_node knode_bus;
	struct module_kobject *mkobj;
	struct device_driver *driver;
};
#define to_driver(obj) container_of(obj, struct driver_private, kobj)


/**
 * struct class_private - structure to hold the private to the driver core portions of the class structure.
 *
 * @class_subsys - the struct kset that defines this class.  This is the main kobject
 * @class_devices - list of devices associated with this class
 * @class_interfaces - list of class_interfaces associated with this class
 * @class_dirs - "glue" directory for virtual devices associated with this class
 * @class_mutex - mutex to protect the children, devices, and interfaces lists.
 * @class - pointer back to the struct class that this structure is associated
 * with.
 *
 * This structure is the one that is the actual kobject allowing struct
 * class to be statically allocated safely.  Nothing outside of the driver
 * core should ever touch these fields.
 */
struct class_private {
	struct kset class_subsys;//代表class在sysfs中的位置
	struct klist class_devices;//是class下的设备链表  device{}->knode_class
	struct list_head class_interfaces;//class 接口 class_interface 它允许class driver在class下有设备添加或移除的时候，调用预先设置好的回调函数
	struct kset class_dirs;
	struct mutex class_mutex;//用于保护class内部的数据结构
	struct class *class;//指回struct class的指针
};
#define to_class(obj)	\
	container_of(obj, struct class_private, class_subsys.kobj)

/**
 * struct device_private - structure to hold the private to the driver core portions of the device structure.
 *
 * @klist_children - klist containing all children of this device
 * @knode_parent - node in sibling list
 * @knode_driver - node in driver list
 * @knode_bus - node in bus list
 * @driver_data - private pointer for driver specific info.  Will turn into a
 * list soon.
 * @device - pointer back to the struct class that this structure is
 * associated with.
 *
 * Nothing outside of the driver core should ever touch these fields.
 */
 //device_private{}和device描述的是设备
struct device_private 
{
	struct klist klist_children;//本设备孩子链表的表头
	struct klist_node knode_parent;//连接到所属父设备的孩子链表的连接件
	struct klist_node knode_driver;//driver_private{}->klist_devices  driver_private和device_driver描述的是驱动 连接到驱动
	struct klist_node knode_bus; //bus_type_private{}->klist_devices  bus_type_private和bus_type描述的是总线 连接到所属于的总线
	void *driver_data;//指向驱动私有数据指针
	struct device *device;//指向所属于的设备
};

#define to_device_private_parent(obj)	\
	container_of(obj, struct device_private, knode_parent)
#define to_device_private_driver(obj)	\
	container_of(obj, struct device_private, knode_driver)
#define to_device_private_bus(obj)	\
	container_of(obj, struct device_private, knode_bus)

extern int device_private_init(struct device *dev);

/* initialisation functions */
extern int devices_init(void);
extern int buses_init(void);
extern int classes_init(void);
extern int firmware_init(void);
#ifdef CONFIG_SYS_HYPERVISOR
extern int hypervisor_init(void);
#else
static inline int hypervisor_init(void) { return 0; }
#endif
extern int platform_bus_init(void);
extern int system_bus_init(void);
extern int cpu_dev_init(void);

extern int bus_add_device(struct device *dev);
extern void bus_probe_device(struct device *dev);
extern void bus_remove_device(struct device *dev);

extern int bus_add_driver(struct device_driver *drv);
extern void bus_remove_driver(struct device_driver *drv);

extern void driver_detach(struct device_driver *drv);
extern int driver_probe_device(struct device_driver *drv, struct device *dev);
static inline int driver_match_device(struct device_driver *drv,
				                                 struct device *dev)
{
	return drv->bus->match ? drv->bus->match(dev, drv) : 1;
}

extern void sysdev_shutdown(void);

extern char *make_class_name(const char *name, struct kobject *kobj);

extern int devres_release_all(struct device *dev);

extern struct kset *devices_kset;

#if defined(CONFIG_MODULES) && defined(CONFIG_SYSFS)
extern void module_add_driver(struct module *mod, struct device_driver *drv);
extern void module_remove_driver(struct device_driver *drv);
#else
static inline void module_add_driver(struct module *mod,
				     struct device_driver *drv) { }
static inline void module_remove_driver(struct device_driver *drv) { }
#endif

#ifdef CONFIG_DEVTMPFS
extern int devtmpfs_init(void);
#else
static inline int devtmpfs_init(void) { return 0; }
#endif
