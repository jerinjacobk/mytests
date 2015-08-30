all:
	aarch64-thunderx-linux-gnu-gcc test.c -O3 -g && aarch64-thunderx-linux-gnu-objdump -D a.out > log.txt

linaro:
	aarch64-linux-gnu-gcc -O3 -g test.c  && aarch64-linux-gnu-objdump -D a.out > log.txt

o2:
	aarch64-thunderx-linux-gnu-gcc test.c -O2 -g  && aarch64-thunderx-linux-gnu-objdump -D a.out > log.txt

static:
	aarch64-thunderx-linux-gnu-gcc test.c -O3 -g --static  && aarch64-thunderx-linux-gnu-objdump -D a.out > log.txt

x86:
	gcc -O3 -g test.c && objdump -D a.out > log.txt
