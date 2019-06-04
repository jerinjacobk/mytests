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

void print128_u16_num(uint16x8_t var)
{
	uint16_t *val = (uint16_t*) &var;
	printf("u16: %x %x %x %x %x %x %x %x\n",
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

#if 0
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
#endif

void x(void)
{
	uint16x8_t x = {1, 2, 3, 4, 5, 6, 7, 8};
	uint64x2_t x64;
	uint32_t sig;

	print128_u16_num(x);

	x64 = vpaddlq_u32(vpaddlq_u16(x));

	print128_num(x64);

	sig = (uint32_t)(vgetq_lane_u64(x64, 0) + vgetq_lane_u64(x64, 1));

	printf("sig=%x\n", sig);

	sig = (uint32_t)(vaddvq_u16(x));
	printf("sig=%x\n", sig);
}

int main()
{
	init();

	x();

	return 0;
}
