#ifndef SSE2ALTIVEC_H
#define SSE2ALTIVEC_H

#include <altivec.h>
#undef bool

typedef __vector unsigned char __m128i;
typedef __vector double __m128d;
typedef __vector unsigned long long __m128ll;

typedef float __m128 __attribute__ ((__vector_size__ (16), __may_alias__));

#if defined(__GNUC__) || defined(__clang__)
#	pragma pop_macro("ALIGN_STRUCT")
#	pragma pop_macro("FORCE_INLINE")
#endif

#endif