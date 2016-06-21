#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define INLINE inline __attribute__((always_inline))
#define NOINLINE inline __attribute__((noinline))

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

static INLINE __m128i _mm_setzero_si128()
{
#if 0
        __m128i out;
        asm volatile(
                "movi %[out].4S, #0" "\n\t"
                :[out]"=w"(out)
                );
        return out;
#else
	return vdupq_n_s32(0);
#endif
}

static INLINE void _mm_store_si128(__m128i *p, __m128i a)
{
	vst1q_s32((int32_t*) p,a);
}


static INLINE __m128i _mm_unpackhi_epi64 (__m128i a, __m128i b)
{
        __m128i out;
        asm volatile(
                "mov %[out].D[0], %[a].D[1]" "\n\t"
                "mov %[out].D[1], %[b].D[1]" "\n\t"
                :[out]"=w"(out)
                :[a]"w"(a),[b]"w"(b)
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


void print128_u16_num(__m128i var)
{
	uint16_t *val = (uint16_t*) &var;
	printf("u16: %i %i %i %i %i %i %i %i \n",
           val[7], val[6], val[5], val[4], val[3], val[2],
           val[1], val[0]);
}

void print128_u8_num(__m128i var)
{
	uint8_t *val = (uint8_t*) &var;
	printf("u8: %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i\n",
           val[15], val[14], val[13], val[12], val[11], val[10],
           val[9], val[8], val[7], val[6], val[5], val[4],
	   val[3], val[2], val[1], val[0]);
}

void print128_s8_num(__m128i var)
{
	int8_t *val = (uint8_t*) &var;
	printf("s8: %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i\n",
           val[15], val[14], val[13], val[12], val[11], val[10],
           val[9], val[8], val[7], val[6], val[5], val[4],
	   val[3], val[2], val[1], val[0]);
}

void print128_num(__m128i var)
{
	int64_t *v64val = (int64_t*) &var;
	printf("%.16llx %.16llx\n", v64val[1], v64val[0]);
}

void test0(void)
{
#if 0
	__m128i var;
	__m128i a;
	__m128i b;
	var = _mm_set_epi64x(0xdeadbeef, 0x12345678);
	print128_num(var);

	var = _mm_setzero_si128();
	print128_num(var);

	a = _mm_set_epi64x(0xdeadbeef, 0x12345678);
	print128_num(a);
	b = _mm_set_epi64x(0x9abcdef, 0xaaaaabbbb);
	print128_num(b);
	var = _mm_unpackhi_epi64(a, b);
	print128_num(var);
#else

#if 0
	var = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);
	mask = _mm_set_epi64x(0x8080808080808080, 0x8080808080808001);
	res = _mm_shuffle_epi8(var, mask);
#endif
#if 0
	var = _mm_set_epi64x(0xFF00000000000000, 0x070000000f000000);
	res = _mm_srli_epi32(var, 30);
#endif
#endif
}

void test1(void)
{
	__m128i var;
	__m128i mask;
	__m128i res;

	print128_num(res);

}

int main()
{
	test1();
	return 0;
}

