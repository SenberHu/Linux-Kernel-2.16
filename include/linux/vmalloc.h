#ifndef _LINUX_VMALLOC_H
#define _LINUX_VMALLOC_H

#include <linux/spinlock.h>
#include <linux/init.h>
#include <asm/page.h>		/* pgprot_t */

struct vm_area_struct;		/* vma defining user mapping in mm_types.h */

/* bits in flags of vmalloc's vm_struct below */
#define VM_IOREMAP	0x00000001	/* ioremap() and friends *///表示将几乎随机的物理内存区域映射到vmalloc区域中. 这是一个特定于体系结构的操作
#define VM_ALLOC	0x00000002	/* vmalloc() *///指定由vmalloc产生的子区域
#define VM_MAP		0x00000004	/* vmap()ed pages 用于表示将现存pages集合映射到连续的虚拟地址空间中*/
#define VM_USERMAP	0x00000008	/* suitable for remap_vmalloc_range */
#define VM_VPAGES	0x00000010	/* buffer for pages was vmalloc'ed */
/* bits [20..32] reserved for arch specific ioremap internals */

/*
 * Maximum alignment for ioremap() regions.
 * Can be overriden by arch-specific value.
 */
#ifndef IOREMAP_MAX_ORDER
#define IOREMAP_MAX_ORDER	(7 + PAGE_SHIFT)	/* 128 pages */
#endif

//对于vmalloc分配的子区域 都对应内存中一个该结构 vmlist为链表头 VMALLOC_START为第一个节点的地址
//和用户空间对应(vm_area_struct)，内核使用vm_struct。只是内核所有的vm_struct放在一起，与单个进程无关
struct vm_struct {
	struct vm_struct	*next;//所有的vm_struct通过next 组成一个单链表，表头为全局变量vmlist
	void			    *addr;//分配的子区域在虚拟地址中的起始地址
	unsigned long		size;//vmalloc分配的该子区域的长度
	unsigned long		flags;//存储了与该内存区关联的标志VM_ALLOC
	struct page		**pages;//是一个指针，指向page指针的数组，每个数组成员都表示一个映射到这个地址空间的物理页面的实例
	unsigned int		nr_pages; //pages数组中页的个数
	unsigned long		phys_addr; //仅当用ioremap映射了由物理地址描述的物理内存区域才有效。
	void			*caller;
};

/*
 *	Highlevel APIs for driver use
 */
extern void vm_unmap_ram(const void *mem, unsigned int count);
extern void *vm_map_ram(struct page **pages, unsigned int count,
				int node, pgprot_t prot);
extern void vm_unmap_aliases(void);

#ifdef CONFIG_MMU
extern void __init vmalloc_init(void);
#else
static inline void vmalloc_init(void)
{
}
#endif

extern void *vmalloc(unsigned long size);
extern void *vmalloc_user(unsigned long size);
extern void *vmalloc_node(unsigned long size, int node);
extern void *vmalloc_exec(unsigned long size);
extern void *vmalloc_32(unsigned long size);
extern void *vmalloc_32_user(unsigned long size);
extern void *__vmalloc(unsigned long size, gfp_t gfp_mask, pgprot_t prot);
extern void *__vmalloc_area(struct vm_struct *area, gfp_t gfp_mask,
				pgprot_t prot);
extern void vfree(const void *addr);

extern void *vmap(struct page **pages, unsigned int count,
			unsigned long flags, pgprot_t prot);
extern void vunmap(const void *addr);

extern int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
							unsigned long pgoff);
void vmalloc_sync_all(void);
 
/*
 *	Lowlevel-APIs (not for driver use!)
 */

static inline size_t get_vm_area_size(const struct vm_struct *area)
{
	/* return actual size without guard page */
	return area->size - PAGE_SIZE;
}

//试图在虚拟的vmalloc空间中找到一个适当的位置
extern struct vm_struct *get_vm_area(unsigned long size, unsigned long flags);

extern struct vm_struct *get_vm_area_caller(unsigned long size,unsigned long flags, void *caller);
extern struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
					unsigned long start, unsigned long end);
extern struct vm_struct *__get_vm_area_caller(unsigned long size,
					unsigned long flags,
					unsigned long start, unsigned long end,
					void *caller);
extern struct vm_struct *get_vm_area_node(unsigned long size,
					  unsigned long flags, int node,
					  gfp_t gfp_mask);
extern struct vm_struct *remove_vm_area(const void *addr);

extern int map_vm_area(struct vm_struct *area, pgprot_t prot,
			struct page ***pages);
extern int map_kernel_range_noflush(unsigned long start, unsigned long size,
				    pgprot_t prot, struct page **pages);
extern void unmap_kernel_range_noflush(unsigned long addr, unsigned long size);
extern void unmap_kernel_range(unsigned long addr, unsigned long size);

/* Allocate/destroy a 'vmalloc' VM area. */
extern struct vm_struct *alloc_vm_area(size_t size);
extern void free_vm_area(struct vm_struct *area);

/* for /dev/kmem */
extern long vread(char *buf, char *addr, unsigned long count);
extern long vwrite(char *buf, char *addr, unsigned long count);

/*
 *	Internals.  Dont't use..
 */
extern rwlock_t vmlist_lock;


extern struct vm_struct *vmlist;
extern __init void vm_area_register_early(struct vm_struct *vm, size_t align);

#ifndef CONFIG_HAVE_LEGACY_PER_CPU_AREA
struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
				     const size_t *sizes, int nr_vms,
				     size_t align, gfp_t gfp_mask);
#endif

void pcpu_free_vm_areas(struct vm_struct **vms, int nr_vms);

#endif /* _LINUX_VMALLOC_H */
