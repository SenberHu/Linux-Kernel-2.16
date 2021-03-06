#ifndef _ASM_X86_CMPXCHG_32_H
#define _ASM_X86_CMPXCHG_32_H

#include <linux/bitops.h> /* for LOCK_PREFIX */

/*
 * Note: if you use set64_bit(), __cmpxchg64(), or their variants, you
 *       you need to test for the feature in boot_cpu_data.
 */

#define xchg(ptr, v)							\
	((__typeof__(*(ptr)))__xchg((unsigned long)(v), (ptr), sizeof(*(ptr))))

struct __xchg_dummy {
	unsigned long a[100];
};
#define __xg(x) ((struct __xchg_dummy *)(x))

/*
 * The semantics of XCHGCMP8B are a bit strange, this is why
 * there is a loop and the loading of %%eax and %%edx has to
 * be inside. This inlines well in most cases, the cached
 * cost is around ~38 cycles. (in the future we might want
 * to do an SIMD/3DNOW!/MMX/FPU 64-bit store here, but that
 * might have an implicit FPU-save as a cost, so it's not
 * clear which path to go.)
 *
 * cmpxchg8b must be used with the lock prefix here to allow
 * the instruction to be executed atomically, see page 3-102
 * of the instruction set reference 24319102.pdf. We need
 * the reader side to see the coherent 64bit value.
 */
static inline void __set_64bit(unsigned long long *ptr,
			       unsigned int low, unsigned int high)
{
	asm volatile("\n1:\t"
		     "movl (%1), %%eax\n\t"
		     "movl 4(%1), %%edx\n\t"
		     LOCK_PREFIX "cmpxchg8b %0\n\t"
		     "jnz 1b"
		     : "=m"(*ptr)
		     : "D" (ptr),
		       "b"(low),
		       "c"(high)
		     : "ax", "dx", "memory");
}

static inline void __set_64bit_constant(unsigned long long *ptr,
					unsigned long long value)
{
	__set_64bit(ptr, (unsigned int)value, (unsigned int)(value >> 32));
}

#define ll_low(x)	*(((unsigned int *)&(x)) + 0)
#define ll_high(x)	*(((unsigned int *)&(x)) + 1)

static inline void __set_64bit_var(unsigned long long *ptr,
				   unsigned long long value)
{
	__set_64bit(ptr, ll_low(value), ll_high(value));
}

#define set_64bit(ptr, value)			\
	(__builtin_constant_p((value))		\
	 ? __set_64bit_constant((ptr), (value))	\
	 : __set_64bit_var((ptr), (value)))

#define _set_64bit(ptr, value)						\
	(__builtin_constant_p(value)					\
	 ? __set_64bit(ptr, (unsigned int)(value),			\
		       (unsigned int)((value) >> 32))			\
	 : __set_64bit(ptr, ll_low((value)), ll_high((value))))

/*
 * Note: no "lock" prefix even on SMP: xchg always implies lock anyway
 * Note 2: xchg has side effect, so that attribute volatile is necessary,
 *	  but generally the primitive is invalid, *ptr is output argument. --ANK
 */
static inline unsigned long __xchg(unsigned long x, volatile void *ptr,
				   int size)
{
	switch (size) {
	case 1:
		asm volatile("xchgb %b0,%1"
			     : "=q" (x), "+m" (*__xg(ptr))
			     : "0" (x)
			     : "memory");
		break;
	case 2:
		asm volatile("xchgw %w0,%1"
			     : "=r" (x), "+m" (*__xg(ptr))
			     : "0" (x)
			     : "memory");
		break;
	case 4:
		asm volatile("xchgl %0,%1"
			     : "=r" (x), "+m" (*__xg(ptr))
			     : "0" (x)
			     : "memory");
		break;
	}
	return x;
}

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */

#ifdef CONFIG_X86_CMPXCHG
#define __HAVE_ARCH_CMPXCHG 1
#define cmpxchg(ptr, o, n)						\
	((__typeof__(*(ptr)))__cmpxchg((ptr), (unsigned long)(o),	\
				       (unsigned long)(n),		\
				       sizeof(*(ptr))))
#define sync_cmpxchg(ptr, o, n)						\
	((__typeof__(*(ptr)))__sync_cmpxchg((ptr), (unsigned long)(o),	\
					    (unsigned long)(n),		\
					    sizeof(*(ptr))))
#define cmpxchg_local(ptr, o, n)					\
	((__typeof__(*(ptr)))__cmpxchg_local((ptr), (unsigned long)(o),	\
					     (unsigned long)(n),	\
					     sizeof(*(ptr))))
#endif

#ifdef CONFIG_X86_CMPXCHG64
#define cmpxchg64(ptr, o, n)						\
	((__typeof__(*(ptr)))__cmpxchg64((ptr), (unsigned long long)(o), \
					 (unsigned long long)(n)))
#define cmpxchg64_local(ptr, o, n)					\
	((__typeof__(*(ptr)))__cmpxchg64_local((ptr), (unsigned long long)(o), \
					       (unsigned long long)(n)))
#endif

static inline unsigned long __cmpxchg(volatile void *ptr, unsigned long old,
				      unsigned long new, int size)
{
	unsigned long prev;
	switch (size) {
	case 1:
		asm volatile(LOCK_PREFIX "cmpxchgb %b2,%1"
			     : "=a"(prev), "+m"(*__xg(ptr))
			     : "q"(new), "0"(old)
			     : "memory");
		return prev;
	case 2:
		asm volatile(LOCK_PREFIX "cmpxchgw %w2,%1"
			     : "=a"(prev), "+m"(*__xg(ptr))
			     : "r"(new), "0"(old)
			     : "memory");
		return prev;
	case 4:
		asm volatile(LOCK_PREFIX "cmpxchgl %2,%1"
			     : "=a"(prev), "+m"(*__xg(ptr))
			     : "r"(new), "0"(old)
			     : "memory");
		return prev;
	}
	return old;
}

/*
 * Always use locked operations when touching memory shared with a
 * hypervisor, since the system may be SMP even if the guest kernel
 * isn't.
 */
static inline unsigned long __sync_cmpxchg(volatile void *ptr,
					   unsigned long old,
					   unsigned long new, int size)
{
	unsigned long prev;
	switch (size) {
	case 1:
		asm volatile("lock; cmpxchgb %b2,%1"
			     : "=a"(prev), "+m"(*__xg(ptr))
			     : "q"(new), "0"(old)
			     : "memory");
		return prev;
	case 2:
		asm volatile("lock; cmpxchgw %w2,%1"
			     : "=a"(prev), "+m"(*__xg(ptr))
			     : "r"(new), "0"(old)
			     : "memory");
		return prev;
	case 4:
		asm volatile("lock; cmpxchgl %2,%1"
			     : "=a"(prev), "+m"(*__xg(ptr))
			     : "r"(new), "0"(old)
			     : "memory");
		return prev;
	}
	return old;
}

static inline unsigned long __cmpxchg_local(volatile void *ptr,
					    unsigned long old,
					    unsigned long new, int size)
{
	unsigned long prev;
	switch (size) {
	case 1:
		asm volatile("cmpxchgb %b2,%1"
			     : "=a"(prev), "+m"(*__xg(ptr))
			     : "q"(new), "0"(old)
			     : "memory");
		return prev;
	case 2:
		asm volatile("cmpxchgw %w2,%1"
			     : "=a"(prev), "+m"(*__xg(ptr))
			     : "r"(new), "0"(old)
			     : "memory");
		return prev;
	case 4:
		asm volatile("cmpxchgl %2,%1"
			     : "=a"(prev), "+m"(*__xg(ptr))
			     : "r"(new), "0"(old)
			     : "memory");
		return prev;
	}
	return old;
}

static inline unsigned long long __cmpxchg64(volatile void *ptr,
					     unsigned long long old,
					     unsigned long long new)
{
	unsigned long long prev;
	asm volatile(LOCK_PREFIX "cmpxchg8b %1"
		     : "=A"(prev), "+m" (*__xg(ptr))
		     : "b"((unsigned long)new),
		       "c"((unsigned long)(new >> 32)),
		       "0"(old)
		     : "memory");
	return prev;
}

static inline unsigned long long __cmpxchg64_local(volatile void *ptr,
						   unsigned long long old,
						   unsigned long long new)
{
	unsigned long long prev;
	asm volatile("cmpxchg8b %1"
		     : "=A"(prev), "+m"(*__xg(ptr))
		     : "b"((unsigned long)new),
		       "c"((unsigned long)(new >> 32)),
		       "0"(old)
		     : "memory");
	return prev;
}

#ifndef CONFIG_X86_CMPXCHG
/*
 * Building a kernel capable running on 80386. It may be necessary to
 * simulate the cmpxchg on the 80386 CPU. For that purpose we define
 * a function for each of the sizes we support.
 */

extern unsigned long cmpxchg_386_u8(volatile void *, u8, u8);
extern unsigned long cmpxchg_386_u16(volatile void *, u16, u16);
extern unsigned long cmpxchg_386_u32(volatile void *, u32, u32);

static inline unsigned long cmpxchg_386(volatile void *ptr, unsigned long old,
					unsigned long new, int size)
{
	switch (size) {
	case 1:
		return cmpxchg_386_u8(ptr, old, new);
	case 2:
		return cmpxchg_386_u16(ptr, old, new);
	case 4:
		return cmpxchg_386_u32(ptr, old, new);
	}
	return old;
}

#define cmpxchg(ptr, o, n)						\
({									\
	__typeof__(*(ptr)) __ret;					\
	if (likely(boot_cpu_data.x86 > 3))				\
		__ret = (__typeof__(*(ptr)))__cmpxchg((ptr),		\
				(unsigned long)(o), (unsigned long)(n),	\
				sizeof(*(ptr)));			\
	else								\
		__ret = (__typeof__(*(ptr)))cmpxchg_386((ptr),		\
				(unsigned long)(o), (unsigned long)(n),	\
				sizeof(*(ptr)));			\
	__ret;								\
})
#define cmpxchg_local(ptr, o, n)					\
({									\
	__typeof__(*(ptr)) __ret;					\
	if (likely(boot_cpu_data.x86 > 3))				\
		__ret = (__typeof__(*(ptr)))__cmpxchg_local((ptr),	\
				(unsigned long)(o), (unsigned long)(n),	\
				sizeof(*(ptr)));			\
	else								\
		__ret = (__typeof__(*(ptr)))cmpxchg_386((ptr),		\
				(unsigned long)(o), (unsigned long)(n),	\
				sizeof(*(ptr)));			\
	__ret;								\
})
#endif

#ifndef CONFIG_X86_CMPXCHG64
/*
 * Building a kernel capable running on 80386 and 80486. It may be necessary
 * to simulate the cmpxchg8b on the 80386 and 80486 CPU.
 */

extern unsigned long long cmpxchg_486_u64(volatile void *, u64, u64);

#define cmpxchg64(ptr, o, n)					\
({								\
	__typeof__(*(ptr)) __ret;				\
	__typeof__(*(ptr)) __old = (o);				\
	__typeof__(*(ptr)) __new = (n);				\
	alternative_io("call cmpxchg8b_emu",			\
			"lock; cmpxchg8b (%%esi)" ,		\
		       X86_FEATURE_CX8,				\
		       "=A" (__ret),				\
		       "S" ((ptr)), "0" (__old),		\
		       "b" ((unsigned int)__new),		\
		       "c" ((unsigned int)(__new>>32))		\
		       : "memory");				\
	__ret; })



#define cmpxchg64_local(ptr, o, n)					\
({									\
	__typeof__(*(ptr)) __ret;					\
	if (likely(boot_cpu_data.x86 > 4))				\
		__ret = (__typeof__(*(ptr)))__cmpxchg64_local((ptr),	\
				(unsigned long long)(o),		\
				(unsigned long long)(n));		\
	else								\
		__ret = (__typeof__(*(ptr)))cmpxchg_486_u64((ptr),	\
				(unsigned long long)(o),		\
				(unsigned long long)(n));		\
	__ret;								\
})

#endif

#endif /* _ASM_X86_CMPXCHG_32_H */
