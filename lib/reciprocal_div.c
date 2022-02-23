#include <asm/div64.h>
#include <linux/reciprocal_div.h>

u32 reciprocal_value(u32 k)
{
	u64 val = (1LL << 32) + (k - 1);
    //val = val / k;
	do_div(val, k);
	return (u32)val;
}
