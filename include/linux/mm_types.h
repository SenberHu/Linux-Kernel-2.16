#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/auxvec.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/prio_tree.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/page-debug-flags.h>
#include <asm/page.h>
#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

struct address_space;

#define USE_SPLIT_PTLOCKS	(NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS)

#if USE_SPLIT_PTLOCKS
typedef atomic_long_t mm_counter_t;
#else  /* !USE_SPLIT_PTLOCKS */
typedef unsigned long mm_counter_t;
#endif /* !USE_SPLIT_PTLOCKS */

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 */

//page_zone()根据page获得管理区
struct page {

	//通过set_page_links()设置页面属于哪个节点哪个区
	//存储了体系结构无关的标志,用于描述页的属性  PG_error
	unsigned long flags;		

	//使用page_count()检查该变量. 
	//该函数返回 0 表示页空闲返回 大于0的数表示页在被使用
	//引用计数，表示内核中引用该page的次数，如果要操作该page，引用计数会+1，操作完成-1。当该值为0时，表示没有引用该page的位置，所以该page可以被解除映射，这往往在内存回收时是有用的
	atomic_t _count;		
					 
	union {
		atomic_t _mapcount;	/* Count of ptes mapped in mms,
					 * to show when page is mapped
					 * & limit reverse map searches.
					 */
					 /*
                         初始值为-1 在该页被插入到逆向映射数据结构 计数器加1
                         逆向映射是给定一个page能找到所有使用该页的进程
					  */
					 /*被页表映射的次数，也就是说该page同时被多少个进程共享。初始值为-1，如果只被一个进程的页表映射了，该值为0 。如果该page处于伙伴系统中，该值为PAGE_BUDDY_MAPCOUNT_VALUE（-128），内核通过判断该值是否为PAGE_BUDDY_MAPCOUNT_VALUE来确定该page是否属于伙伴系统。*/

		struct 	
		{	
			u16 inuse; //用于SLUB分配器，对象的数目
			u16 objects;
		};
	};
					 
	union {
	    struct 
		{
			/*
				如果设置了PagePrivate 通常用于buffer_heads
				如果设置了PageSwapCache 则用于swap_entry_t 
				如果设置了PG_buddy 则用于伙伴系统的阶
			*/
			unsigned long private;

			/*
			    如果最低位为0 则指向inode->address_pace,或为NULL
			    如果最低位置位，则为匿名映射，该指针指向anon_vma对象
				anon_vma = (struct anon_vma *)(mapping - PAGE_MAPPING_ANON)
			*/
			struct address_space *mapping;//看page_lock_anon_vma()
	    };
		
#if USE_SPLIT_PTLOCKS
	    spinlock_t ptl;
#endif
	    struct kmem_cache *slab;	/* SLUB: Pointer to slab //用于SLUB分配器，指向slab的指针*/
	    struct page *first_page;	/*内核可以将多个毗邻的页合并为较大的复合页，分组中的第一个页为首页,
	                                  而其他页叫做尾页 */
	};

	
	union 
	{
		pgoff_t index;		/* Our offset within mapping.//在映射内的偏移量   */
		void *freelist;		/* SLUB: freelist req. slab lock */
	};

     //对于slab 此值另做他用page_set_slab()和page_set_cache()
	//是一个表头，用于在各种链表上维护该页，一遍将页按不用类别分组，最重要的类别是活动页和不活动页					             
	//根据页面替换策略可能被换出的页面存放在active_list或inactive_list链表中
	struct list_head lru;		/* Pageout list, eg. active_list
					 			   *protected by zone->lru_lock !
									换出页列表
					 			   */
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
//用于特定的结构如摩托罗拉 ，其他体系查找高端内存用散列表
#if defined(WANT_PAGE_VIRTUAL)  //page_address()用此宏来对此字段进行访问
	void *virtual;			/* Kernel virtual address (NULL if
					           not kmapped, ie. highmem)
							   内核虚拟地址 如果没有映射则为NULL，用于高端内存 	

					           */
#endif /* WANT_PAGE_VIRTUAL */

#ifdef CONFIG_WANT_PAGE_DEBUG_FLAGS
	unsigned long debug_flags;	/* Use atomic bitops on this */
#endif

#ifdef CONFIG_KMEMCHECK
	/*
	 * kmemcheck wants to track the status of each byte in a page; this
	 * is a pointer to such a status block. NULL if not tracked.
	 */
	void *shadow;
#endif

};

/*
 * A region containing a mapping of a non-memory backed file under NOMMU
 * conditions.  These are held in a global tree and are pinned by the VMAs that
 * map parts of them.
 */
struct vm_region {
	struct rb_node	vm_rb;		/* link in global region tree */
	unsigned long	vm_flags;	/* VMA vm_flags */
	unsigned long	vm_start;	/* start address of region */
	unsigned long	vm_end;		/* region initialised to here */
	unsigned long	vm_top;		/* region allocated to here */
	unsigned long	vm_pgoff;	/* the offset in vm_file corresponding to vm_start */
	struct file	*vm_file;	/* the backing file or NULL */

	atomic_t	vm_usage;	/* region usage count */
};

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
 /*
vm_area_struct是虚存管理的基础单元，它描述的是一段连续的、具有相同访问属性的虚存空间。
一个进程使用到的不同的虚存空间的访问属性可能不同，所以就需要多个vm_area_struct来对其进行描述
*/
struct vm_area_struct {
	struct mm_struct * vm_mm;	/* The address space we belong to. 指向上级结构mm_struct*/
	
	unsigned long vm_start;		/* Our start address within vm_mm. 虚拟内存区间的开始地址*/
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. 虚拟内存区间的结束地址*/

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next, *vm_prev;  //双向链表 连接所有的虚拟内存区间

	pgprot_t vm_page_prot;		/* Access permissions of this VMA. 该虚拟内存区域的访问权限*/
	unsigned long vm_flags;		/* Flags, VM_READ  see mm.h. 和体系机构无关的区间属性 低4位可用也页表项的低四位*/

	struct rb_node vm_rb; //红黑树连接点  为了快速定位地址属于哪个区间 所以采用红黑树

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap prio tree, or
	 * linkage to the list of like vmas hanging off its node, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 */
	/* shared联合体用于和address space关联 */
	union {
		struct {
			struct list_head list;/* 用于链入非线性映射的链表 */
			void *parent;	/* aligns with prio_tree_node parent */
			struct vm_area_struct *head;
		} vm_set;

		struct raw_prio_tree_node prio_tree_node;/*线性映射则链入i_mmap优先树*/
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	//用于管理源自匿名映射的共享页  指向相同页的映射都保存在一个双链表上anon_vma_node充当链表元素
	struct list_head anon_vma_node;	/* Serialized by anon_vma->lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock 匿名vma对象*/

	/* Function pointers to deal with this struct. */
	const struct vm_operations_struct *vm_ops; //将文件系统file操作集放到此处

	/* Information about our backing store: */
	//文件映射的偏移量,该值只用于映射了文件的部分内容(整个文件映射的话此值为0)
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE 在文件中的偏移*/
				   	
	struct file * vm_file;		/* File we map to (can be NULL).  被映射的文件*/
	void * vm_private_data;		/* was vm_pte (shared mem) 私有数据*/
	unsigned long vm_truncate_count;/* truncate_count or restart_addr */

#ifndef CONFIG_MMU
	struct vm_region *vm_region;	/* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

//内存描述符的结构体 mm_struct结构描述了一个进程的整个虚拟地址空间
//vm_area_truct描述了虚拟地址空间的一个区间（简称虚拟区）
struct mm_struct {
	struct vm_area_struct * mmap;		/* list of VMAs *///指向虚拟内存区间的链表头
											//用cat /proc/PID/maps 可以看到不同的虚拟内存空间
											
	struct rb_root mm_rb;////指向虚拟内存区间的红黑树
	struct vm_area_struct * mmap_cache;	/* 上一次find_vma的结果*/

	//用来在进程地址空间中搜索有效的进程地址空间的函数
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);

	//释放线性区时调用的方法， 
	void (*unmap_area) (struct mm_struct *mm, unsigned long addr);
	
	unsigned long mmap_base;		/* base of mmap area 虚拟地址空间中用于内存映射的起始地址
                                       调用get_unmapped_area()在mmap区域为新映射找到合适的位置
	                                   */

	unsigned long task_size;		/* 存储了对应进程的地址空间长度 该值通常为TASK_SIZE
                                       但在64上执行32位程序  此值为该进程真正可见的长度
									   */
									   
	unsigned long cached_hole_size; 	/* if non-zero, the largest hole below free_area_cache */

	 //内核进程搜索进程地址空间中线性地址的空间
	unsigned long free_area_cache;		/* first hole of size cached_hole_size or larger */

	//指向页表的目录 
	//进程页表的载入是将pgd放入cr3寄存器
	pgd_t * pgd;

	//使用地址空间的用户数 比如两个线程贡献此结构则此值为2
	atomic_t mm_users;			/* How many users with user space? */

	//内存描述符的主使用计数器，采用引用计数的原理，当为0时代表无用户再次使用
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */

	 //线性区的个数
	int map_count;				/* number of VMAs */
	struct rw_semaphore mmap_sem;

	  //保护任务页表和引用计数的锁
	spinlock_t page_table_lock;		/* Protects page tables and some counters */

    //所有mm_struct形成的链表 链表的首元素为init_mm 操作此链表需要锁mmlist_lock
	struct list_head mmlist;		/* List of maybe swapped mm's.	These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/* Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	mm_counter_t _file_rss;
	mm_counter_t _anon_rss;

	//进程拥有的最大页表数目
	unsigned long hiwater_rss;	/* High-watermark of RSS usage */

	//进程线性区的最大页表数目
	unsigned long hiwater_vm;	/* High-water virtual memory usage */

	 //进程地址空间的大小，锁住无法换页的个数，共享文件内存映射的页数，可执行内存映射中的页数
	unsigned long total_vm, locked_vm, shared_vm, exec_vm;
	unsigned long stack_vm, 
		          reserved_vm, 
		          def_flags, //为0或VM_LOCKED  VM_LOCKED标志映射的页无法被换出 此标志需要来mlockall系统调用来设置VM_LOCKED
		          nr_ptes;

	              //维护code段
	unsigned long start_code,
		          end_code,

				  //维护data段
		          start_data, 
		          end_data;
	
	unsigned long start_brk, //堆的起始地址
		          brk, //堆区域当前的结束地址
		          
		          start_stack;//是用来维护stack段空间范围
		          
	unsigned long arg_start,//参数起始地址  
		          arg_end,  //参数结束地址
		           
		          env_start,//环境变量起始地址 
		          env_end;//环境变量结束地址

	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

	struct linux_binfmt *binfmt;

	cpumask_t cpu_vm_mask;

	/* Architecture-specific MM context */
	mm_context_t context;//体系结构特殊数据

	/* Swap token stuff */
	/*
	 * Last value of global fault stamp as seen by this process.
	 * In other words, this value gives an indication of how long
	 * it has been since this task got the token.
	 * Look at mm/thrash.c
	 */
	unsigned int faultstamp;
	unsigned int token_priority;
	unsigned int last_interval;

	unsigned long flags; /* 状态标志 */

	struct core_state *core_state; /* coredumping support 核心转储的支持*/
#ifdef CONFIG_AIO
	spinlock_t		ioctx_lock;//AIO IO链表锁
	struct hlist_head	ioctx_list; //AIO IO链表
#endif
#ifdef CONFIG_MM_OWNER
	/*
	 * "owner" points to a task that is regarded as the canonical
	 * user/owner of this mm. All of the following must be true in
	 * order for it to be changed:
	 *
	 * current == mm->owner
	 * current->mm != mm
	 * new_owner->mm == mm
	 * new_owner->alloc_lock is held
	 */
	struct task_struct *owner;
#endif

#ifdef CONFIG_PROC_FS
	/* store ref to file /proc/<pid>/exe symlink points to */
	struct file *exe_file;
	unsigned long num_exe_file_vmas;
#endif
#ifdef CONFIG_MMU_NOTIFIER
	struct mmu_notifier_mm *mmu_notifier_mm;
#endif
};

/* Future-safe accessor for struct mm_struct's cpu_vm_mask. */
#define mm_cpumask(mm) (&(mm)->cpu_vm_mask)

#endif /* _LINUX_MM_TYPES_H */
