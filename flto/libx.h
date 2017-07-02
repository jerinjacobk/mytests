#ifndef __LIBX_H__
#define __LIBX_H__

struct worker {
        int datum;
        void (*do_work)(struct worker *, int i);
};

extern void do_work (struct worker *elab, const int i);

void libx_rx_init(int slot, void (*f)(struct worker *, int i));
void libx_rx_burst(int slot);

#endif //__LIBX_H__
