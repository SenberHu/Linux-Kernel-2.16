#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <linux/mmzone.h>
#include <linux/stddef.h>
#include <linux/linkage.h>
#include <linux/topology.h>
#include <linux/mmdebug.h>

struct vm_area_struct;

/*
 * GFP bitmasks..
 *
 * Zone modifiers (see linux/mmzone.h - low three bits)
 *
 * Do not put any conditional on these. If necessary modify the definitions
 * without the underscores and use the consistently. The definitions here may
 * be used in bit comparisons.
 */
 //GFP get free page

/*
会将下面8中错误的组合写到一个表中 即GFP_ZONE_BAD

__GFP_DMA   __GFP_HIGHMEM    __GFP_DMA32   __GFP_MOVABLE   结果
   0            0               0              0           从GFP_NORMAL中分配
   1            0               0              0           从NORMAL或DMA分配
   0            1               0              0           从NORMAL或HIGHMEM分配
   1            1               0              0           不能同时满足 错误    (_GFP_DMA | GFP_HIGHMEM)
   0            0               1              0           从NORMAL或DMA32
   1            0               1              0           不能同时满足  错误   (__GFP_DMA | __GFP_DMA32)
   0            1               1              0            不能同时满足 错误   (__GFP_HIGHMEM | __GFP_DMA32)
   1            1               1              0            不能同时满足错误    (__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32)
   0            0               0              1           从NORMAL 或MOVABLE
   1            0               0              1           从NORMAL或MOVABLE+DMA
   0            1               0              1           从MOVABLE获得
   1            1               0              1           错误                 (__GFP_DMA|__GFP_HIGHMEM|__GFP_MOVABLE__GFP_MOVABLE)
   0            0               1              1           ZONE_DMA
   1            0               1              1           错误                 (__GFP_DMA|__GFP_DMA32|__GFP_MOVABLE)
   0            1               1              1           错误                 (__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)
   1            1               1              1           错误                 (__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)
*/
#define __GFP_DMA	((__force gfp_t)0x01u)  //0x01
#define __GFP_HIGHMEM	((__force gfp_t)0x02u)//这个标志指示分配的内存可以位于高端内存.
#define __GFP_DMA32	((__force gfp_t)0x04u)
#define __GFP_MOVABLE	((__force gfp_t)0x08u)  /* Page is movable 从可移动内存分配*/

//gfp的低三位来表示从哪个zone获得
#define GFP_ZONEMASK	(__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)
/*
 * Action modifiers - doesn't change the zoning
 *
 * __GFP_REPEAT: Try hard to allocate the memory, but the allocation attempt
 * _might_ fail.  This depends upon the particular VM implementation.
 *
 * __GFP_NOFAIL: The VM implementation _must_ retry infinitely: the caller
 * cannot handle allocation failures.
 *
 * __GFP_NORETRY: The VM implementation must not retry indefinitely.
 *
 * __GFP_MOVABLE: Flag that this page will be movable by the page migration
 * mechanism or reclaimed
 */
#define __GFP_WAIT	((__force gfp_t)0x10u)	/* Can wait and reschedule?  分配器可以睡眠*/

//表示内核急切的需要内存 内存分配失败可能给内核带来严重后果时 会用此标志
#define __GFP_HIGH	((__force gfp_t)0x20u)	/* Should access emergency pools? *///这个标志标识了一个高优先级请求, 它被允许来消耗甚至被内核保留给紧急状况的最后的内存页.

//在查找空闲内存期间内核可以进行IO操作, 这意味着如果内核在内存分配期间换出页，只有在设置此标志时 才能将选择的页写回磁盘
#define __GFP_IO	((__force gfp_t)0x40u)	/* Can start physical IO? 分配器可以启动磁盘IO*/

//允许内核执行VFS操作 在于vfs层有连续的内核子系统中必须禁用 可能会引起循环递归调用
#define __GFP_FS	((__force gfp_t)0x80u)	/* Can call down to low-level FS?分配器可以启动文件系统 */

//如果需要分配不在cpu 高速缓存的冷页时 则设置此标志
#define __GFP_COLD	((__force gfp_t)0x100u)	/* Cache-cold page required *///正常地, 内存分配器尽力返回"缓冲热"的页 -- 可能在处理器缓冲中找到的页. 相反, 这个标志请求一个"冷"页, 它在一段时间没被使用. 它对分配页作 DMA 读是有用的, 此时在处理器缓冲中出现是无用的

#define __GFP_NOWARN	((__force gfp_t)0x200u)	/* 分配器不打印失败警告 *///这个很少用到的标志阻止内核来发出警告(使用 printk ), 当一个分配无法满足

#define __GFP_REPEAT	((__force gfp_t)0x400u)	/* See above 分配器失败后重新进行分配 但这次存在失败的可能*/

#define __GFP_NOFAIL	((__force gfp_t)0x800u)	/* See above 分配器无限的重复分配  分配不能失败*/

#define __GFP_NORETRY	((__force gfp_t)0x1000u)/* See above 分配器失败后 绝不重新分配*/
#define __GFP_COMP	((__force gfp_t)0x4000u)/* Add compound page metadata 将多个连续物理页合并成巨型TLB页*/
#define __GFP_ZERO	((__force gfp_t)0x8000u)/* Return zeroed page on success 填充0*/
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u) /* Don't use emergency reserves 不使用紧急分配链表*/

//只允许在进程允许运行的cpu所关联的节点分配内存 只在NUMA系统上有意义
//在分配失败的情况下 不允许在其他节点作为备用 
#define __GFP_HARDWALL   ((__force gfp_t)0x20000u) /* Enforce hardwall cpuset memory allocs */

//没有备用节点 没有策略
#define __GFP_THISNODE	((__force gfp_t)0x40000u)/* No fallback, no policies */

//页是可回收的
#define __GFP_RECLAIMABLE ((__force gfp_t)0x80000u) /* Page is reclaimable */

#ifdef CONFIG_KMEMCHECK
#define __GFP_NOTRACK	((__force gfp_t)0x200000u)  /* Don't track with kmemcheck */
#else
#define __GFP_NOTRACK	((__force gfp_t)0)
#endif

/*
 * This may seem redundant, but it's a way of annotating false positives vs.
 * allocations that simply cannot be supported (e.g. page tables).
 */
#define __GFP_NOTRACK_FALSE_POSITIVE (__GFP_NOTRACK)

#define __GFP_BITS_SHIFT 22	/* Room for 22 __GFP_FOO bits */
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))

/* This equals 0, but use constants in case they ever change */
#define GFP_NOWAIT	(GFP_ATOMIC & ~__GFP_HIGH)//与GFP_ATOMIC相似 不同是调用不会退给紧急内存池
/* GFP_ATOMIC means both !wait (__GFP_WAIT not set) and use emergency pool */
#define GFP_ATOMIC	(__GFP_HIGH)//用来从中断处理和进程上下文之外的其他代码中分配内存. 从不睡眠
#define GFP_NOIO	(__GFP_WAIT)//绝不会启动磁盘IO来满足要求
#define GFP_NOFS	(__GFP_WAIT | __GFP_IO)//绝不会启动文件系统

#define GFP_KERNEL	(__GFP_WAIT | __GFP_IO | __GFP_FS)//内核内存的正常分配. 可能睡眠

#define GFP_TEMPORARY	(__GFP_WAIT | __GFP_IO | __GFP_FS | \
			 __GFP_RECLAIMABLE) // 类似于GFP_KERNEL，并且在内存不足时，还允许进行内存回收
#define GFP_USER	(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL)//用来为用户空间页来分配内存; 它可能睡眠.
#define GFP_HIGHUSER	(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | \ //如同 GFP_USER, 但是从高端内存分配, 如果有. 高端内存在下一个子节描述.
			 __GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE	(__GFP_WAIT | __GFP_IO | __GFP_FS | \
				 __GFP_HARDWALL | __GFP_HIGHMEM | \
				 __GFP_MOVABLE)

#ifdef CONFIG_NUMA
#define GFP_THISNODE	(__GFP_THISNODE | __GFP_NOWARN | __GFP_NORETRY)
#else
#define GFP_THISNODE	((__force gfp_t)0)
#endif

/* This mask makes up all the page movable related flags */
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)

/* Control page allocator reclaim behavior */
#define GFP_RECLAIM_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS|\
			__GFP_NOWARN|__GFP_REPEAT|__GFP_NOFAIL|\
			__GFP_NORETRY|__GFP_NOMEMALLOC)

/* Control slab gfp mask during early boot */
#define GFP_BOOT_MASK __GFP_BITS_MASK & ~(__GFP_WAIT|__GFP_IO|__GFP_FS)

/* Control allocation constraints */
#define GFP_CONSTRAINT_MASK (__GFP_HARDWALL|__GFP_THISNODE)

/* Do not use these with a slab allocator */
#define GFP_SLAB_BUG_MASK (__GFP_DMA32|__GFP_HIGHMEM|~__GFP_BITS_MASK)

/* Flag - indicates that the buffer will be suitable for DMA.  Ignored on some
   platforms, used as appropriate on others */

#define GFP_DMA		__GFP_DMA //这个标志要求分配在能够 DMA 的内存区. 确切的含义是平台依赖的

/* 4GB DMA on some platforms */
#define GFP_DMA32	__GFP_DMA32

//根据gfp标志转换成相应的迁移类型
static inline int allocflags_to_migratetype(gfp_t gfp_flags)
{
	WARN_ON((gfp_flags & GFP_MOVABLE_MASK) == GFP_MOVABLE_MASK);

	if (unlikely(page_group_by_mobility_disabled))
		return MIGRATE_UNMOVABLE;

	/* Group based on mobility */
	return (((gfp_flags & __GFP_MOVABLE) != 0) << 1) |
		((gfp_flags & __GFP_RECLAIMABLE) != 0);
}

#ifdef CONFIG_HIGHMEM
#define OPT_ZONE_HIGHMEM ZONE_HIGHMEM
#else
#define OPT_ZONE_HIGHMEM ZONE_NORMAL
#endif

#ifdef CONFIG_ZONE_DMA
#define OPT_ZONE_DMA ZONE_DMA
#else
#define OPT_ZONE_DMA ZONE_NORMAL
#endif

#ifdef CONFIG_ZONE_DMA32
#define OPT_ZONE_DMA32 ZONE_DMA32
#else
#define OPT_ZONE_DMA32 ZONE_NORMAL
#endif

/*
 * GFP_ZONE_TABLE is a word size bitstring that is used for looking up the
 * zone to use given the lowest 4 bits of gfp_t. Entries are ZONE_SHIFT long
 * and there are 16 of them to cover all possible combinations of
 * __GFP_DMA, __GFP_DMA32, __GFP_MOVABLE and __GFP_HIGHMEM
 *
 * The zone fallback order is MOVABLE=>HIGHMEM=>NORMAL=>DMA32=>DMA.
 * But GFP_MOVABLE is not only a zone specifier but also an allocation
 * policy. Therefore __GFP_MOVABLE plus another zone selector is valid.
 * Only 1bit of the lowest 3 bit (DMA,DMA32,HIGHMEM) can be set to "1".
 *
 *       bit       result
 *       =================
 *       0x0    => NORMAL
 *       0x1    => DMA or NORMAL
 *       0x2    => HIGHMEM or NORMAL
 *       0x3    => BAD (DMA+HIGHMEM)
 *       0x4    => DMA32 or DMA or NORMAL
 *       0x5    => BAD (DMA+DMA32)
 *       0x6    => BAD (HIGHMEM+DMA32)
 *       0x7    => BAD (HIGHMEM+DMA32+DMA)
 *       0x8    => NORMAL (MOVABLE+0)
 *       0x9    => DMA or NORMAL (MOVABLE+DMA)
 *       0xa    => MOVABLE (Movable is valid only if HIGHMEM is set too)
 *       0xb    => BAD (MOVABLE+HIGHMEM+DMA)
 *       0xc    => DMA32 (MOVABLE+HIGHMEM+DMA32)
 *       0xd    => BAD (MOVABLE+DMA32+DMA)
 *       0xe    => BAD (MOVABLE+DMA32+HIGHMEM)
 *       0xf    => BAD (MOVABLE+DMA32+HIGHMEM+DMA)
 *
 * ZONES_SHIFT must be <= 2 on 32 bit platforms.
 */

#if 16 * ZONES_SHIFT > BITS_PER_LONG
#error ZONES_SHIFT too large to create GFP_ZONE_TABLE integer
#endif
//__GFP_DMA上面的表格
/*
OPT_ZONE_DMA代表 GFP_NORMAL 或者 GFP_NORMAL
OPT_ZONE_HGIHMEM 代表 GFP_NORMAL 或者 GFP_HIGHMEM
OPT_ZONE_DMA32 代表 GFP_NORMAL 或者 GFP_DMA32
ZONES_SHIFT:每个选项的位宽

*/
#define GFP_ZONE_TABLE ( \
	(ZONE_NORMAL << 0 * ZONES_SHIFT)				\
	| (OPT_ZONE_DMA << __GFP_DMA * ZONES_SHIFT) 			\
	| (OPT_ZONE_HIGHMEM << __GFP_HIGHMEM * ZONES_SHIFT)		\
	| (OPT_ZONE_DMA32 << __GFP_DMA32 * ZONES_SHIFT)			\
	| (ZONE_NORMAL << __GFP_MOVABLE * ZONES_SHIFT)			\
	| (OPT_ZONE_DMA << (__GFP_MOVABLE | __GFP_DMA) * ZONES_SHIFT)	\
	| (ZONE_MOVABLE << (__GFP_MOVABLE | __GFP_HIGHMEM) * ZONES_SHIFT)\
	| (OPT_ZONE_DMA32 << (__GFP_MOVABLE | __GFP_DMA32) * ZONES_SHIFT)\
)

/*
 * GFP_ZONE_BAD is a bitmap for all combination of __GFP_DMA, __GFP_DMA32
 * __GFP_HIGHMEM and __GFP_MOVABLE that are not permitted. One flag per
 * entry starting with bit 0. Bit is set if the combination is not
 * allowed.
 */
 //__GFP_DMA上面的表格
#define GFP_ZONE_BAD ( \
	1 << (__GFP_DMA | __GFP_HIGHMEM)				\
	| 1 << (__GFP_DMA | __GFP_DMA32)				\
	| 1 << (__GFP_DMA32 | __GFP_HIGHMEM)				\
	| 1 << (__GFP_DMA | __GFP_DMA32 | __GFP_HIGHMEM)		\
	| 1 << (__GFP_MOVABLE | __GFP_HIGHMEM | __GFP_DMA)		\
	| 1 << (__GFP_MOVABLE | __GFP_DMA32 | __GFP_DMA)		\
	| 1 << (__GFP_MOVABLE | __GFP_DMA32 | __GFP_HIGHMEM)		\
	| 1 << (__GFP_MOVABLE | __GFP_DMA32 | __GFP_DMA | __GFP_HIGHMEM)\
)

//根据gfp_flags 获得内存区域
static inline enum zone_type gfp_zone(gfp_t flags)
{
	enum zone_type z;
	int bit = flags & GFP_ZONEMASK;

	z = (GFP_ZONE_TABLE >> (bit * ZONES_SHIFT)) & ((1 << ZONES_SHIFT) - 1);

    //下面检查是否错误的区域组合
	if (__builtin_constant_p(bit))
		MAYBE_BUILD_BUG_ON((GFP_ZONE_BAD >> bit) & 1);
	else {
#ifdef CONFIG_DEBUG_VM
		BUG_ON((GFP_ZONE_BAD >> bit) & 1);
#endif
	}
	return z;
}

/*
 * There is only one page-allocator function, and two main namespaces to
 * it. The alloc_page*() variants return 'struct page *' and as such
 * can allocate highmem pages, the *get*page*() variants return
 * virtual kernel addresses to the allocated page(s).
 */

static inline int gfp_zonelist(gfp_t flags)
{
	if (NUMA_BUILD && unlikely(flags & __GFP_THISNODE))
		return 1;

	return 0;
}

/*
 * We get the zone list from the current node and the gfp_mask.
 * This zone list contains a maximum of MAXNODES*MAX_NR_ZONES zones.
 * There are two zonelists per node, one for all zones with memory and
 * one containing just zones from the node the zonelist belongs to.
 *
 * For the normal case of non-DISCONTIGMEM systems the NODE_DATA() gets
 * optimized to &contig_page_data at compile-time.
 */
static inline struct zonelist *node_zonelist(int nid, gfp_t flags)
{
	return NODE_DATA(nid)->node_zonelists + gfp_zonelist(flags);
}

#ifndef HAVE_ARCH_FREE_PAGE
static inline void arch_free_page(struct page *page, int order) { }
#endif
#ifndef HAVE_ARCH_ALLOC_PAGE
static inline void arch_alloc_page(struct page *page, int order) { }
#endif

struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
		       struct zonelist *zonelist, nodemask_t *nodemask);

//伙伴系统分配的主函数
static inline struct page *__alloc_pages(gfp_t gfp_mask, unsigned int order,
		                                         struct zonelist *zonelist)
{
	return __alloc_pages_nodemask(gfp_mask, order, zonelist, NULL);
}

static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,unsigned int order)
{
	/* Unknown node is current node */
	if (nid < 0)
		nid = numa_node_id();//获得当前cpu节点

	return __alloc_pages(gfp_mask, order, node_zonelist(nid, gfp_mask));
}

static inline struct page *alloc_pages_exact_node(int nid, gfp_t gfp_mask,
						unsigned int order)
{
	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);

	//从伙伴系统进行分配
	return __alloc_pages(gfp_mask, order, node_zonelist(nid, gfp_mask));
}

#ifdef CONFIG_NUMA
extern struct page *alloc_pages_current(gfp_t gfp_mask, unsigned order);

//申请的内存以页为单位,最小也是一个页 可以使用__get_free_pages() 此函数封装了 alloc_page()和page_address()

/*
gfp_mask: 分配标志，如GFP_ATOMIC、GFP_KERNEL等等
order:	要分配的页面数量为2^order，要分配一个页面，指定order为0.
*/
static inline struct page *
alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	return alloc_pages_current(gfp_mask, order);
}

extern struct page *alloc_page_vma(gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr);
#else
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define alloc_page_vma(gfp_mask, vma, addr) alloc_pages(gfp_mask, 0)
#endif
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

extern unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);

//分配一个页 并且将页内容填充0
extern unsigned long get_zeroed_page(gfp_t gfp_mask);

void *alloc_pages_exact(size_t size, gfp_t gfp_mask);
void free_pages_exact(void *virt, size_t size);

#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask),0)

//用来获得适用于DMA的页
#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA,(order))

extern void __free_pages(struct page *page, unsigned int order);
extern void free_pages(unsigned long addr, unsigned int order);
extern void free_hot_page(struct page *page);

#define __free_page(page) __free_pages((page), 0)
#define free_page(addr) free_pages((addr),0)

void page_alloc_init(void);
void drain_zone_pages(struct zone *zone, struct per_cpu_pages *pcp);
void drain_all_pages(void);
void drain_local_pages(void *dummy);

extern gfp_t gfp_allowed_mask;

static inline void set_gfp_allowed_mask(gfp_t mask)
{
	gfp_allowed_mask = mask;
}

#endif /* __LINUX_GFP_H */
