#ifndef __ASM_GENERIC_CURRENT_H
#define __ASM_GENERIC_CURRENT_H

#include <linux/thread_info.h>


/*

*****************
*               *
*               *
*    内核堆栈   *
*      |        *
*      |        *
*     \|/       *
*               *       ------->task_struct{stack} 
*               *       |                     |
*---------------*       |                     |
* thread_info{} *--------                    \|/
*****************<-----------------------------

*/
#define get_current() (current_thread_info()->task)
#define current get_current()

#endif /* __ASM_GENERIC_CURRENT_H */
