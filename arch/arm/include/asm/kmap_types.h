#ifndef __ARM_KMAP_TYPES_H
#define __ARM_KMAP_TYPES_H

/*
 * This is the "bare minimum".  AIO seems to require this.
 */
enum km_type {
	KM_BOUNCE_READ,
	KM_SKB_SUNRPC_DATA,
	KM_SKB_DATA_SOFTIRQ,
	
	KM_USER0, //这两个对驱动有意义 针对在用户空间直接运行的代码
	KM_USER1,

	KM_BIO_SRC_IRQ,
	KM_BIO_DST_IRQ,
	KM_PTE0,
	KM_PTE1,
	
	KM_IRQ0, //这两个针对中断处理程序
	KM_IRQ1,


	KM_SOFTIRQ0,
	KM_SOFTIRQ1,
	KM_L2_CACHE,
	KM_TYPE_NR
};

#ifdef CONFIG_DEBUG_HIGHMEM
#define KM_NMI		(-1)
#define KM_NMI_PTE	(-1)
#define KM_IRQ_PTE	(-1)
#endif

#endif
