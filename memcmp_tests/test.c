#include <stdio.h>
#include <arm_neon.h>
#include <string.h>
#include "rte_cmp_arm64.h"
#include "rte_cmp_simd_arm64.h"


#define rte_compiler_barrier() do {             \
        asm volatile ("" : : : "memory");	\
} while(0)

static inline uint64_t
rte_rdtsc(void)
{
        uint64_t tsc;
	rte_compiler_barrier();
        asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
        return tsc;
}

#define NR_ITERATION	10000000

typedef int (*rte_hash_cmp_eq_t)(const void *key1, const void *key2, size_t key_len);

char __attribute__((aligned(128))) a[128]= {0xf, 0x0, 0x4, 0x5, 0x6, 0xf, 0x6, 0xc, 0xf, 0x7, 0xff, 0x00};
char __attribute__((aligned(128))) b[128]= {0xf, 0x0, 0x4, 0x5, 0x6, 0xf, 0x6, 0xc, 0xf, 0x7, 0xff, 0x00};

struct _fn_tbl
{
	rte_hash_cmp_eq_t fnptr;
	uint64_t ticks;
	int result;
	int size;
	int last;
	char name[32];

} fn_tbl [] =
{
	{
		memcmp,
		0,
		0xffffffff,
		16,
		0,
		"memcmp",
	},
	{
		neon_rte_hash_k16_cmp_eq,
		0,
		0xffffffff,
		16,
		0,
		"neon_rte_hash_k16_cmp_eq",
	},
	{
		rte_hash_k16_cmp_eq,
		0,
		0xffffffff,
		16,
		1,
		"rte_hash_k16_cmp_eq"
	},
	{
		memcmp,
		0,
		0xffffffff,
		32,
		0,
		"memcpy",
	},
	{
		neon_rte_hash_k32_cmp_eq,
		0,
		0xffffffff,
		32,
		0,
		"neon_rte_hash_k32_cmp_eq",
	},
	{
		rte_hash_k32_cmp_eq,
		0,
		0xffffffff,
		32,
		1,
		"rte_hash_k32_cmp_eq"
	},
	{
		memcmp,
		0,
		0xffffffff,
		48,
		0,
		"memcpy",
	},
	{
		neon_rte_hash_k48_cmp_eq,
		0,
		0xffffffff,
		48,
		0,
		"neon_rte_hash_k48_cmp_eq",
	},
	{
		rte_hash_k48_cmp_eq,
		0,
		0xffffffff,
		48,
		1,
		"rte_hash_k48_cmp_eq"
	},
	{
		memcmp,
		0,
		0xffffffff,
		64,
		0,
		"memcpy",
	},
	{
		neon_rte_hash_k64_cmp_eq,
		0,
		0xffffffff,
		64,
		0,
		"neon_rte_hash_k64_cmp_eq",
	},
	{
		rte_hash_k64_cmp_eq,
		0,
		0xffffffff,
		64,
		1,
		"rte_hash_k64_cmp_eq"
	},
	{
		memcmp,
		0,
		0xffffffff,
		80,
		0,
		"memcpy",
	},
	{
		neon_rte_hash_k80_cmp_eq,
		0,
		0xffffffff,
		80,
		0,
		"neon_rte_hash_k80_cmp_eq",
	},
	{
		rte_hash_k80_cmp_eq,
		0,
		0xffffffff,
		80,
		1,
		"rte_hash_k80_cmp_eq"
	},
	{
		memcmp,
		0,
		0xffffffff,
		96,
		0,
		"memcpy",
	},
	{
		neon_rte_hash_k96_cmp_eq,
		0,
		0xffffffff,
		96,
		0,
		"neon_rte_hash_k96_cmp_eq",
	},
	{
		rte_hash_k96_cmp_eq,
		0,
		0xffffffff,
		96,
		1,
		"rte_hash_k96_cmp_eq"
	},
	{
		memcmp,
		0,
		0xffffffff,
		112,
		0,
		"memcpy",
	},
	{
		neon_rte_hash_k112_cmp_eq,
		0,
		0xffffffff,
		112,
		0,
		"neon_rte_hash_k112_cmp_eq",
	},
	{
		rte_hash_k112_cmp_eq,
		0,
		0xffffffff,
		112,
		1,
		"rte_hash_k112_cmp_eq"
	},
	{
		memcmp,
		0,
		0xffffffff,
		128,
		0,
		"memcpy",
	},
	{
		neon_rte_hash_k128_cmp_eq,
		0,
		0xffffffff,
		128,
		0,
		"neon_rte_hash_k128_cmp_eq",
	},
	{
		rte_hash_k128_cmp_eq,
		0,
		0xffffffff,
		128,
		1,
		"rte_hash_k128_cmp_eq"
	},
};

static __attribute__ ((noinline))
uint64_t run_test(rte_hash_cmp_eq_t fn, int* result, int size)
{
	int i;
	uint64_t start, delta;
	volatile register int test = 0;

	start = rte_rdtsc();
	for(i = 0; i < NR_ITERATION; i++)
		test += fn(a, b, size);
	delta = rte_rdtsc() - start;

	*result = test;
	return delta;
}

int main()
{
	int i;

	for (i = 0; i < sizeof(fn_tbl)/sizeof(struct _fn_tbl); i++) {
		fn_tbl[i].ticks = run_test(fn_tbl[i].fnptr, &fn_tbl[i].result,
					fn_tbl[i].size);

		if (fn_tbl[i].last) {
			printf("%-28s len=%-4u (Ticks/OP)=%.02f result=%d gain(wrt glibc)=%f\%\n",
				fn_tbl[i-2].name, fn_tbl[i-2].size, (double)fn_tbl[i-2].ticks/ NR_ITERATION, fn_tbl[i-2].result,
				((((double)fn_tbl[i-2].ticks/ NR_ITERATION) / ((double)fn_tbl[i-2].ticks/ NR_ITERATION))* 100)- 100);
			printf("%-28s len=%-4u (Ticks/OP)=%.02f result=%d gain(wrt glibc)=%f\%\n",
				fn_tbl[i-1].name, fn_tbl[i-1].size, (double)fn_tbl[i-1].ticks/ NR_ITERATION, fn_tbl[i-1].result,
				((((double)fn_tbl[i-2].ticks/ NR_ITERATION) / ((double)fn_tbl[i-1].ticks/ NR_ITERATION))* 100)- 100);
			printf("%-28s len=%-4u (Ticks/OP)=%.02f result=%d gain(wrt glibc)=%f\%\n\n",
				fn_tbl[i-0].name, fn_tbl[i-0].size, (double)fn_tbl[i-0].ticks/ NR_ITERATION, fn_tbl[i-0].result,
				((((double)fn_tbl[i-2].ticks/ NR_ITERATION) / ((double)fn_tbl[i-0].ticks/ NR_ITERATION))* 100)- 100);
		}
	}
	return 0;
}

