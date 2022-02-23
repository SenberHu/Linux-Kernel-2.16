#ifndef _ASM_X86_CACHE_H
#define _ASM_X86_CACHE_H

#include <linux/linkage.h>

/* L1 cache line size */
#define L1_CACHE_SHIFT	(CONFIG_X86_L1_CACHE_SHIFT)
#define L1_CACHE_BYTES	(1 << L1_CACHE_SHIFT)

/*****************************
它标记了前面这个变量是很经常被读取的,
如果在有缓存的平台上，它就能把这个变量存放到cache中，以保证后续读取的速度
这里的意思是将这个数据链接进data.read_mostly段
***********************************************/
#define __read_mostly __attribute__((__section__(".data.read_mostly")))

#ifdef CONFIG_X86_VSMP
/* vSMP Internode cacheline shift */
#define INTERNODE_CACHE_SHIFT (12)
#ifdef CONFIG_SMP
#define __cacheline_aligned_in_smp					\
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))	\
	__page_aligned_data
#endif
#endif

#endif /* _ASM_X86_CACHE_H */
