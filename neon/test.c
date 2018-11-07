#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "arm_neon.h"

#define INLINE inline __attribute__((always_inline))
#define NOINLINE inline __attribute__((noinline))

void print128_u32_num(uint32x4_t var)
{
	uint32_t *val = (uint32_t*) &var;
	printf("u32: %4llx %4llx %4llx %4llx \n",
           val[3], val[2], val[1], val[0]);
}

void print128_u16_num(uint64x2_t var)
{
	uint16_t *val = (uint16_t*) &var;
	printf("u16: %2llxx %2lxx %2llx %2llx %2llx %2llx %2llx %2llx\n",
           val[7], val[6], val[5], val[4], val[3], val[2],
           val[1], val[0]);
}

void print128_u8_num(uint64x2_t var)
{
	uint8_t *val = (uint8_t*) &var;
	printf("u8: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
           val[15], val[14], val[13], val[12], val[11], val[10],
           val[9], val[8], val[7], val[6], val[5], val[4],
	   val[3], val[2], val[1], val[0]);
}

void print128_s8_num(uint64x2_t var)
{
	int8_t *val = (uint8_t*) &var;
	printf("s8: %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i\n",
           val[15], val[14], val[13], val[12], val[11], val[10],
           val[9], val[8], val[7], val[6], val[5], val[4],
	   val[3], val[2], val[1], val[0]);
}

void print128_num(uint64x2_t var)
{
	int64_t *v64val = (int64_t*) &var;
	printf("%.16llx %.16llx\n", v64val[1], v64val[0]);
}

uint64_t ptr_array[64];
void init(void)
{
	ptr_array[0] = 0x0001020304050607;
	ptr_array[1] = 0x08090a0b0c0d0e0f;

}


void vshlq_u32_test(void)
{
	uint32x4_t new;
	uint32x4_t val = vld1q_u32((uint32_t *)(ptr_array));
	int32x4_t len_shl = {0, 0, 0, 10};

	new = vshlq_u32(val, len_shl);

	print128_u32_num(val);
	print128_u32_num((uint32x4_t)(len_shl));
	print128_u32_num(new);
}

int main()
{
	init();
	vshlq_u32_test();
	return 0;
}
