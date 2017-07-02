#include <stdlib.h>
#include "libx.h"

struct worker wrk[16];

static inline void __do_work(struct worker *wrk, const int i)
{
        wrk->datum += i;
}

void do_work(struct worker *wrk, const int i)
{
	__do_work(wrk, i);
}

void libx_rx_init(int slot, void (*f)(struct worker *wrk, const int i))
{

	struct worker *w = &wrk[slot];
	wrk->do_work = f;
	wrk->datum = 0;
}

void libx_rx_burst(int slot)
{
	struct worker *w = &wrk[slot];

	__do_work(w, 0);
}

