#ifndef ARCH__X86__MM__KMEMCHECK__SHADOW_H
#define ARCH__X86__MM__KMEMCHECK__SHADOW_H

enum kmemcheck_shadow {
	KMEMCHECK_SHADOW_UNALLOCATED,  //非法访问 未分配的（在SLAB中，新分配的slab页面中没有被分配object的部分会被设置成此状态）
	KMEMCHECK_SHADOW_UNINITIALIZED,//非法访问  未初始化的（一般情况下，新分配的页面都会被设置成此状态）
	KMEMCHECK_SHADOW_INITIALIZED,//初始化的（对它的访问是正确的）
	KMEMCHECK_SHADOW_FREED,//非法访问  释放的（在SLAB中，当object被释放后，其所占用的内存会被设置成此状态）
};

void *kmemcheck_shadow_lookup(unsigned long address);

enum kmemcheck_shadow kmemcheck_shadow_test(void *shadow, unsigned int size);
void kmemcheck_shadow_set(void *shadow, unsigned int size);

#endif
