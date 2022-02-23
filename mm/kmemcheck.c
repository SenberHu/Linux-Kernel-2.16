#include <linux/gfp.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kmemcheck.h>

/*
调用alloc_pages_node()分配相同大小的影子内存，其“不被跟踪”（__GFP_NOTRACK）；
将影子页的地址赋予每个对应跟踪页描述符中的shadow字段；
将每个跟踪页置位“不存在”（~_PAGE_PRESENT）和“隐藏”（_PAGE_HIDDEN）。
*/
void kmemcheck_alloc_shadow(struct page *page, int order, gfp_t flags, int node)
{
	struct page *shadow;
	int pages;
	int i;

	pages = 1 << order;

	/*
	 * With kmemcheck enabled, we need to allocate a memory area for the
	 * shadow bits as well.
	 */
	shadow = alloc_pages_node(node, flags | __GFP_NOTRACK, order);
	if (!shadow) {
		if (printk_ratelimit())
			printk(KERN_ERR "kmemcheck: failed to allocate "
				"shadow bitmap\n");
		return;
	}

	for(i = 0; i < pages; ++i)
		page[i].shadow = page_address(&shadow[i]);

	/*
	 * Mark it as non-present for the MMU so that our accesses to
	 * this memory will trigger a page fault and let us analyze
	 * the memory accesses.
	 */
	kmemcheck_hide_pages(page, pages);
}

/*
将每个跟踪页置位“存在”（_PAGE_PRESENT）和“不隐藏”（~_PAGE_HIDDEN）；
将每个跟踪页的shadow字段置为NULL；
调用__free_pages()释放对应的影子内存。
*/
void kmemcheck_free_shadow(struct page *page, int order)
{
	struct page *shadow;
	int pages;
	int i;

	if (!kmemcheck_page_is_tracked(page))
		return;

	pages = 1 << order;

	kmemcheck_show_pages(page, pages);

	shadow = virt_to_page(page[0].shadow);

	for(i = 0; i < pages; ++i)
		page[i].shadow = NULL;

	__free_pages(shadow, order);
}

/*
调用kmemcheck_mark_uninitialized()将跟踪对象所对应的影子内存置位“未初始化”。
（Kmemcheck允许被跟踪页中的部分对象为不被跟踪的，这通过将其影子置位为“初始化”来实现）

*/
void kmemcheck_slab_alloc(struct kmem_cache *s, gfp_t gfpflags, void *object,
			  size_t size)
{
	/*
	 * Has already been memset(), which initializes the shadow for us
	 * as well.
	 */
	if (gfpflags & __GFP_ZERO)
		return;

	/* No need to initialize the shadow of a non-tracked slab. */
	if (s->flags & SLAB_NOTRACK)
		return;

	if (!kmemcheck_enabled || gfpflags & __GFP_NOTRACK) {
		/*
		 * Allow notracked objects to be allocated from
		 * tracked caches. Note however that these objects
		 * will still get page faults on access, they just
		 * won't ever be flagged as uninitialized. If page
		 * faults are not acceptable, the slab cache itself
		 * should be marked NOTRACK.
		 */
		kmemcheck_mark_initialized(object, size);
	} else if (!s->ctor) {
		/*
		 * New objects should be marked uninitialized before
		 * they're returned to the called.
		 */
		kmemcheck_mark_uninitialized(object, size);
	}
}

void kmemcheck_slab_free(struct kmem_cache *s, void *object, size_t size)
{
    //调用kmemcheck_mark_freed()将跟踪对象所对应的影子内存置位为“已释放”
	/* TODO: RCU freeing is unsupported for now; hide false positives. */
	if (!s->ctor && !(s->flags & SLAB_DESTROY_BY_RCU))
		kmemcheck_mark_freed(object, size);
}

/*
调用kmemcheck_alloc_shadow()分配影子内存并标记跟踪内存；
若此内存需被跟踪，则置位其影子为“未初始化”；否则为“初始化”。
*/
void kmemcheck_pagealloc_alloc(struct page *page, unsigned int order,
			       gfp_t gfpflags)
{
	int pages;

	if (gfpflags & (__GFP_HIGHMEM | __GFP_NOTRACK))
		return;

	pages = 1 << order;

	/*
	 * NOTE: We choose to track GFP_ZERO pages too; in fact, they
	 * can become uninitialized by copying uninitialized memory
	 * into them.
	 */

	/* XXX: Can use zone->node for node? */
	kmemcheck_alloc_shadow(page, order, gfpflags, -1);

	if (gfpflags & __GFP_ZERO)
		kmemcheck_mark_initialized_pages(page, pages);
	else
		kmemcheck_mark_uninitialized_pages(page, pages);
}
