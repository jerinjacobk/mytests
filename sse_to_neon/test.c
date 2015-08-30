#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define INLINE inline __attribute__((always_inline))
#define NOINLINE inline __attribute__((no_inline))

#ifdef __aarch64__

#include "arm_neon.h"

typedef float32x4_t __m128;
typedef int32x4_t __m128i;

static INLINE __m128i _mm_set_epi64x(int64_t i1, int64_t i0)
{
        __m128i out;
        asm volatile(
                "ins %[out].D[0], %x[i0]" "\n\t"
                "ins %[out].D[1], %x[i1]" "\n\t"
                :[out]"=w"(out)
                :[i1]"r"(i1),[i0]"r"(i0)
                );
        return out;
}

#else

#if (defined(__ICC) || (__GNUC__ == 4 &&  __GNUC_MINOR__ < 4))

#ifdef __SSE__
#include <xmmintrin.h>
#endif

#ifdef __SSE2__
#include <emmintrin.h>
#endif

#ifdef __SSE3__
#include <tmmintrin.h>
#endif

#if defined(__SSE4_2__) || defined(__SSE4_1__)
#include <smmintrin.h>
#endif

#if defined(__AVX__)
#include <immintrin.h>
#endif

#else

#include <x86intrin.h>

#endif

#endif

void print128_s16_num(__m128i var)
{
	uint16_t *val = (uint16_t*) &var;
	printf("Numerical: %i %i %i %i %i %i %i %i \n",
           val[0], val[1], val[2], val[3], val[4], val[5],
           val[6], val[7]);
}
void print128_num(__m128i var)
{
	int64_t *v64val = (int64_t*) &var;
	printf("%.16llx %.16llx\n", v64val[1], v64val[0]);
}

int main()
{
	__m128i var;
	var = _mm_set_epi64x(0xdeadbeef, 0x12345678);
	print128_num(var);
	return 0;
}

