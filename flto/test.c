#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "libx.h"

#if 0 // arch64
static inline uint64_t
rte_rdtsc(void)
{
        uint64_t tsc;
        asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
        return tsc;
}
#else // x86
static inline uint64_t
rte_rdtsc(void)
{
        union {
                uint64_t tsc_64;
                struct {
                        uint32_t lo_32;
                        uint32_t hi_32;
                };
        } tsc;

        asm volatile("rdtsc" :
                     "=a" (tsc.lo_32),
                     "=d" (tsc.hi_32));
        return tsc.tsc_64;
}
#endif

extern struct worker wrk[16];

static inline void rx_burst(int slot)
{
	struct worker *w = &wrk[slot];
	w->do_work(w, 0);
}


int main (void)
{
        unsigned long i;
	uint64_t start, end;

        libx_rx_init(0, do_work);
	struct worker *w = &wrk[0];

	start= rte_rdtsc();

        for (i = 0; i < 100; i++)
		rx_burst(0);

	end = rte_rdtsc();
	printf("cycles: %"PRId64"\n", end - start);
}
