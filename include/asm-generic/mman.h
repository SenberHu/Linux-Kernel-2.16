#ifndef __ASM_GENERIC_MMAN_H
#define __ASM_GENERIC_MMAN_H

#include <asm-generic/mman-common.h>

#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY 只允许对映射区域的写入操作，其他对文件直接写入的操作将会被拒绝*/
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_LOCKED	0x2000		/* pages are locked  将映射区域锁定住，这表示该区域不会被置换*/
#define MAP_NORESERVE	0x4000		/* don't check for reservations 不需要为映射保留空间*/
#define MAP_POPULATE	0x8000		/* populate (prefault) pagetables 填充页表*/
#define MAP_NONBLOCK	0x10000		/* do not block on IO 在IO上操作不阻塞*/
#define MAP_STACK	0x20000		/* give out an address that is best suited for process/thread stacks */
#define MAP_HUGETLB	0x40000		/* create a huge page mapping */

#define MCL_CURRENT	1		/* lock all current mappings */
#define MCL_FUTURE	2		/* lock all future mappings */

#endif /* __ASM_GENERIC_MMAN_H */
