/* XMRig
 * Copyright 2010      Jeff Garzik     <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler          <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones     <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466        <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee       <jayddee246@gmail.com>
 * Copyright 2016      Imran Yusuff    <https://github.com/imranyusuff>
 * Copyright 2017-2018 XMR-Stak        <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett     <https://github.com/vtnerd>
 * Copyright 2018      SChernykh       <https://github.com/SChernykh>
 * Copyright 2018      Timothy Pearson <https://github.com/madscientist159>
 * Copyright 2016-2018 XMRig           <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XMRIG_CRYPTONIGHT_PPC64_H
#define XMRIG_CRYPTONIGHT_PPC64_H


#include "common/crypto/keccak.h"
#include "common/utils/mm_malloc.h"
#include "crypto/CryptoNight.h"
#include "crypto/CryptoNight_constants.h"
#include "crypto/CryptoNight_monero.h"
#include "crypto/FastSqrt_ppc64.h"
#include "crypto/soft_aes.h"


extern "C"
{
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
}

// From GCC
// https://patchwork.ozlabs.org/patch/827215/
static inline __m128d _mm_set1_pd (double __F)
{
  return __extension__ (__m128d){ __F, __F };
}

static inline __m128i _mm_load_si128(__m128i const *a)
{
  return *a;
}

static inline void _mm_store_si128(__m128i *a, __m128i b)
{
  vec_st(b, 0, a);
}

static inline __m128i _mm_set_epi64x(long long __q1, long long __q0)
{
  return (__m128i)(__vector long long){ __q0, __q1 };
}

static inline __m128i _mm_cvtsi64_si128 (long long __A)
{
  return (__m128i)(__vector long long){ __A, 0LL };
}

static inline __m128i _mm_add_epi64 (__m128i __A, __m128i __B)
{
  return (__m128i) ((__vector unsigned long long)__A + (__vector unsigned long long)__B);
}

static inline __m128d _mm_castsi128_pd(__m128i __A)
{
  return (__m128d) __A;
}

static inline __m128 _mm_cvtsi64_ss (__m128 __A, long long __B)
{
  float temp = __B;
  __A[0] = temp;

  return __A;
}

extern __inline __m128 _mm_castsi128(__m128i __A)
{
  return (__m128) __A;
}

extern __inline __m128 _mm_setzero_ps(void)
{
  return __extension__ (__m128){ 0.0f, 0.0f, 0.0f, 0.0f };
}

static inline __m128d _mm_setzero_pd(void)
{
  return (__m128d) vec_splats(0);
}

static inline __m128d _mm_setr_pd (double __W, double __X)
{
  return (__m128d){ __W, __X };
}

static inline __m128d _mm_sqrt_sd (__m128d __A, __m128d __B)
{
  __vector double c;
  c = vec_sqrt ((__vector double ) _mm_set1_pd (__B[0]));
  return (__m128d ) _mm_setr_pd (c[0], __A[1]);
}

static inline __m128i _mm_castpd_si128(__m128d __A)
{
  return (__m128i) __A;
}

static inline long long _mm_cvtsi128_si64 (__m128i __A)
{
  return ((__vector long long)__A)[0];
}

static inline __m128d _mm_cvtsi64_sd (__m128d __A, long long __B)
{
  __vector double result = (__vector double)__A;
  double db = __B;
  result [0] = db;
  return (__m128d)result;
}

static inline __m128i _mm_bsrli_si128 (__m128i __A, const int __N)
{
  __vector unsigned char result;
  const __vector unsigned char zeros =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  if (__N < 16)
    if (__builtin_constant_p(__N))
      {
	/* Would like to use Vector Shift Left Double by Octet
	   Immediate here to use the immediate form and avoid
	   load of __N * 8 value into a separate VR.  */
	result = vec_sld (zeros, (__vector unsigned char) __A, (16 - __N));
      }
    else
      {
	__vector unsigned char shift = vec_splats((unsigned char)(__N*8));
	result = vec_sro ((__vector unsigned char)__A, shift);
      }
    else
    result = zeros;

  return (__m128i) result;
}

static inline __m128i _mm_srli_si128 (__m128i __A, const int __N)
{
  return _mm_bsrli_si128 (__A, __N);
}

static inline __m128i _mm_setzero_si128 (void)
{
  return (__m128i)(__vector int){ 0, 0, 0, 0 };
}
// End from GCC

static inline __m128i _mm_xor_si128 (__m128i __A, __m128i __B)
{
  return vec_xor(__A, __B);
}

static inline __m128i _mm_aesenc_si128(__m128i in, __m128i key)
{
  return v_rev(__builtin_crypto_vcipher(v_rev(in),v_rev(key)));
}

static inline void do_blake_hash(const uint8_t *input, size_t len, uint8_t *output) {
    blake256_hash(output, input, len);
}


static inline void do_groestl_hash(const uint8_t *input, size_t len, uint8_t *output) {
    groestl(input, len * 8, output);
}


static inline void do_jh_hash(const uint8_t *input, size_t len, uint8_t *output) {
    jh_hash(32 * 8, input, 8 * len, output);
}


static inline void do_skein_hash(const uint8_t *input, size_t len, uint8_t *output) {
    xmr_skein(input, output);
}


void (* const extra_hashes[4])(const uint8_t *, size_t, uint8_t *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};


#   ifdef __GNUC__
static inline uint64_t __umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
    unsigned __int128 r = (unsigned __int128) a * (unsigned __int128) b;
    *hi = r >> 64;
    return (uint64_t) r;
}
#   else
    #define __umul128 _umul128
#   endif


// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
	__m128i tmp4;
	tmp4 = vec_slo(tmp1, (__m128i){0x20});
	tmp1 = vec_xor(tmp1, tmp4);
	tmp4 = vec_slo(tmp4, (__m128i){0x20});
	tmp1 = vec_xor(tmp1, tmp4);
	tmp4 = vec_slo(tmp4, (__m128i){0x20});
	tmp1 = vec_xor(tmp1, tmp4);
	return tmp1;
}


template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
	__m128i xout1 = soft_aeskeygenassist<rcon>(*xout2);
	xout1 = vec_perm(xout1,xout1,(__m128i){0xc,0xd,0xe,0xf, 0xc,0xd,0xe,0xf, 0xc,0xd,0xe,0xf, 0xc,0xd,0xe,0xf});
	*xout0 = sl_xor(*xout0);
	*xout0 = vec_xor(*xout0, xout1);
	xout1 = soft_aeskeygenassist<0x00>(*xout0);
	xout1 = vec_perm(xout1,xout1,(__m128i){0x8,0x9,0xa,0xb, 0x8,0x9,0xa,0xb, 0x8,0x9,0xa,0xb, 0x8,0x9,0xa,0xb});
	*xout2 = sl_xor(*xout2);
	*xout2 = vec_xor(*xout2, xout1);
}


template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3, __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
	__m128i xout0, xout2;

	xout0 = vec_ld(0,memory);
	xout2 = vec_ld(16,memory);
	*k0 = xout0;
	*k1 = xout2;

		aes_genkey_sub<0x01>(&xout0, &xout2);
	*k2 = xout0;
	*k3 = xout2;

		aes_genkey_sub<0x02>(&xout0, &xout2);
	*k4 = xout0;
	*k5 = xout2;

		aes_genkey_sub<0x04>(&xout0, &xout2);
	*k6 = xout0;
	*k7 = xout2;

		aes_genkey_sub<0x08>(&xout0, &xout2);
	*k8 = xout0;
	*k9 = xout2;
}


template<bool SOFT_AES>
static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = _mm_aesenc_si128(*x0, key);
	*x1 = _mm_aesenc_si128(*x1, key);
	*x2 = _mm_aesenc_si128(*x2, key);
	*x3 = _mm_aesenc_si128(*x3, key);
	*x4 = _mm_aesenc_si128(*x4, key);
	*x5 = _mm_aesenc_si128(*x5, key);
	*x6 = _mm_aesenc_si128(*x6, key);
	*x7 = _mm_aesenc_si128(*x7, key);
}


inline void mix_and_propagate(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3, __m128i& x4, __m128i& x5, __m128i& x6, __m128i& x7)
{
	__m128i tmp0 = x0;
	x0 = vec_xor(x0, x1);
	x1 = vec_xor(x1, x2);
	x2 = vec_xor(x2, x3);
	x3 = vec_xor(x3, x4);
	x4 = vec_xor(x4, x5);
	x5 = vec_xor(x5, x6);
	x6 = vec_xor(x6, x7);
	x7 = vec_xor(x7, tmp0);
}


template<xmrig::Algo ALGO, size_t MEM, bool SOFT_AES>
static inline void cn_explode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xin0 = vec_ld(4*16, input);
    xin1 = vec_ld(5*16, input);
    xin2 = vec_ld(6*16, input);
    xin3 = vec_ld(7*16, input);
    xin4 = vec_ld(8*16, input);
    xin5 = vec_ld(9*16, input);
    xin6 = vec_ld(10*16, input);
    xin7 = vec_ld(11*16, input);

    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
        for (size_t i = 0; i < 16; i++) {
            aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

            mix_and_propagate(xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
        }
    }

    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8) {
        aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

        vec_st(xin0,i*16, output);
        vec_st(xin1,(i+1)*16, output);
        vec_st(xin2,(i+2)*16, output);
        vec_st(xin3,(i+3)*16, output);
        vec_st(xin4,(i+4)*16, output);
        vec_st(xin5,(i+5)*16, output);
        vec_st(xin6,(i+6)*16, output);
        vec_st(xin7,(i+7)*16, output);
    }
}


template<xmrig::Algo ALGO, size_t MEM, bool SOFT_AES>
static inline void cn_implode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xout0 = vec_ld(4*16, output);
    xout1 = vec_ld(5*16, output);
    xout2 = vec_ld(6*16, output);
    xout3 = vec_ld(7*16, output);
    xout4 = vec_ld(8*16, output);
    xout5 = vec_ld(9*16, output);
    xout6 = vec_ld(10*16, output);
    xout7 = vec_ld(11*16, output);

    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
    {
        xout0 = vec_xor(vec_ld(i*16,input), xout0);
        xout1 = vec_xor(vec_ld((i+1)*16,input), xout1);
        xout2 = vec_xor(vec_ld((i+2)*16,input), xout2);
        xout3 = vec_xor(vec_ld((i+3)*16,input), xout3);
        xout4 = vec_xor(vec_ld((i+4)*16,input), xout4);
        xout5 = vec_xor(vec_ld((i+5)*16,input), xout5);
        xout6 = vec_xor(vec_ld((i+6)*16,input), xout6);
        xout7 = vec_xor(vec_ld((i+7)*16,input), xout7);

        aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
        for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8) {
            xout0 = vec_xor(vec_ld(i*16,input), xout0);
            xout1 = vec_xor(vec_ld((i+1)*16,input), xout1);
            xout2 = vec_xor(vec_ld((i+2)*16,input), xout2);
            xout3 = vec_xor(vec_ld((i+3)*16,input), xout3);
            xout4 = vec_xor(vec_ld((i+4)*16,input), xout4);
            xout5 = vec_xor(vec_ld((i+5)*16,input), xout5);
            xout6 = vec_xor(vec_ld((i+6)*16,input), xout6);
            xout7 = vec_xor(vec_ld((i+7)*16,input), xout7);

            aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }

        for (size_t i = 0; i < 16; i++) {
            aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    vec_st(xout0, 4*16, output);
    vec_st(xout1, 5*16, output);
    vec_st(xout2, 6*16, output);
    vec_st(xout3, 7*16, output);
    vec_st(xout4, 8*16, output);
    vec_st(xout5, 9*16, output);
    vec_st(xout6, 10*16, output);
    vec_st(xout7, 11*16, output);
}


static inline __m128i aes_round_tweak_div(const __m128i &in, const __m128i &key)
{
    alignas(16) uint32_t k[4];
    alignas(16) uint32_t x[4];

    _mm_store_si128((__m128i*) k, key);
    _mm_store_si128((__m128i*) x, vec_xor(in, _mm_set_epi64x(0xffffffffffffffff, 0xffffffffffffffff)));

    #define BYTE(p, i) ((unsigned char*)&x[p])[i]
    k[0] ^= saes_table[0][BYTE(0, 0)] ^ saes_table[1][BYTE(1, 1)] ^ saes_table[2][BYTE(2, 2)] ^ saes_table[3][BYTE(3, 3)];
    x[0] ^= k[0];
    k[1] ^= saes_table[0][BYTE(1, 0)] ^ saes_table[1][BYTE(2, 1)] ^ saes_table[2][BYTE(3, 2)] ^ saes_table[3][BYTE(0, 3)];
    x[1] ^= k[1];
    k[2] ^= saes_table[0][BYTE(2, 0)] ^ saes_table[1][BYTE(3, 1)] ^ saes_table[2][BYTE(0, 2)] ^ saes_table[3][BYTE(1, 3)];
    x[2] ^= k[2];
    k[3] ^= saes_table[0][BYTE(3, 0)] ^ saes_table[1][BYTE(0, 1)] ^ saes_table[2][BYTE(1, 2)] ^ saes_table[3][BYTE(2, 3)];
    #undef BYTE

    return _mm_load_si128((__m128i*)k);
}

static inline __m128i int_sqrt_v2(const uint64_t n0)
{
	return _mm_cvtsi64_si128(SqrtV2::get(n0));
}

static inline void int_sqrt_v2_dual(const uint64_t n0, __m128i* out0, const uint64_t n1, __m128i* out1)
{
	*out0 = _mm_cvtsi64_si128(SqrtV2::get(n0));
	*out1 = _mm_cvtsi64_si128(SqrtV2::get(n1));
}

template<xmrig::Variant VARIANT>
static inline void cryptonight_monero_tweak(uint64_t* mem_out, const uint8_t* l, uint64_t idx, __m128i ax0, __m128i bx0, __m128i bx1, __m128i cx)
{
    if (VARIANT == xmrig::VARIANT_2) {
        VARIANT2_SHUFFLE(l, idx, ax0, bx0, bx1);
        _mm_store_si128((__m128i *)mem_out, _mm_xor_si128(bx0, cx));
    } else {
        __m128i tmp = _mm_xor_si128(bx0, cx);
        mem_out[0] = _mm_cvtsi128_si64(tmp);

	__m128ll tmp1 = (__m128ll)tmp;
	__m128ll tmp2;
	tmp2[0] = tmp1[1];
	tmp2[1] = tmp1[0];
        uint64_t vh = _mm_cvtsi128_si64(tmp2);

        uint8_t x = static_cast<uint8_t>(vh >> 24);
        static const uint16_t table = 0x7531;
        const uint8_t index = (((x >> (VARIANT == xmrig::VARIANT_XTL ? 4 : 3)) & 6) | (x & 1)) << 1;
        vh ^= ((table >> index) & 0x3) << 28;

        mem_out[1] = vh;
    }
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_single_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_V1        = xmrig::cn_base_variant<VARIANT>() == xmrig::VARIANT_1;

    if (IS_V1 && size < 43) {
        memset(output, 0, 32);
        return;
    }

    xmrig::keccak(input, size, ctx[0]->state);

    cn_explode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) ctx[0]->state, (__m128i*) ctx[0]->memory);

    const uint8_t* l0 = ctx[0]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);

    VARIANT1_INIT(0);
    VARIANT2_INIT(0);
    VARIANT2_SET_ROUNDING_MODE();

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i bx1 = _mm_set_epi64x(h0[9] ^ h0[11], h0[8] ^ h0[10]);

    uint64_t idx0 = al0;

    for (size_t i = 0; i < ITERATIONS; i++) {
        __m128i cx;
        if (VARIANT == xmrig::VARIANT_TUBE || !SOFT_AES) {
            cx = _mm_load_si128((__m128i *) &l0[idx0 & MASK]);
        }

        const __m128i ax0 = _mm_set_epi64x(ah0, al0);
        if (VARIANT == xmrig::VARIANT_TUBE) {
            cx = aes_round_tweak_div(cx, ax0);
        }
        else if (SOFT_AES) {
            cx = soft_aesenc((uint32_t*)&l0[idx0 & MASK], ax0);
        }
        else {  
            cx = _mm_aesenc_si128(cx, ax0);
        }

	//__builtin_prefetch(SqrtV2TableLarge);
	//__builtin_prefetch(SqrtV2TableSmall);
	//__builtin_prefetch(SqrtV2Table);

        if (IS_V1 || VARIANT == xmrig::VARIANT_2) {
            cryptonight_monero_tweak<VARIANT>((uint64_t*)&l0[idx0 & MASK], l0, idx0 & MASK, ax0, bx0, bx1, cx);
        } else {
            _mm_store_si128((__m128i *)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));
        }

        idx0 = _mm_cvtsi128_si64(cx);

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*) &l0[idx0 & MASK])[0];
        ch = ((uint64_t*) &l0[idx0 & MASK])[1];
        if (VARIANT == xmrig::VARIANT_2) {
            VARIANT2_INTEGER_MATH(0, cl, cx);
            lo = __umul128(idx0, cl, &hi);
            VARIANT2_SHUFFLE2(l0, idx0 & MASK, ax0, bx0, bx1, hi, lo);
        }
        else {
            lo = __umul128(idx0, cl, &hi);
        }

        al0 += hi;
        ah0 += lo;

        ((uint64_t*)&l0[idx0 & MASK])[0] = al0;

        if (IS_V1 && (VARIANT == xmrig::VARIANT_TUBE || VARIANT == xmrig::VARIANT_RTO)) {
            ((uint64_t*)&l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0 ^ al0;
        } else if (IS_V1) {
            ((uint64_t*)&l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0;
        } else {
            ((uint64_t*)&l0[idx0 & MASK])[1] = ah0;
        }

        al0 ^= cl;
        ah0 ^= ch;
        idx0 = al0;

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            int64_t n = ((int64_t*)&l0[idx0 & MASK])[0];
            int32_t d = ((int32_t*)&l0[idx0 & MASK])[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)&l0[idx0 & MASK])[0] = n ^ q;

            if (VARIANT == xmrig::VARIANT_XHV) {
                d = ~d;
            }

            idx0 = d ^ q;
        }
        if (VARIANT == xmrig::VARIANT_2) {
            bx1 = bx0;
        }
        bx0 = cx;
    }

    cn_implode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) ctx[0]->memory, (__m128i*) ctx[0]->state);

    xmrig::keccakf(h0, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_double_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_V1        = xmrig::cn_base_variant<VARIANT>() == xmrig::VARIANT_1;

    if (IS_V1 && size < 43) {
        memset(output, 0, 64);
        return;
    }

    xmrig::keccak(input,        size, ctx[0]->state);
    xmrig::keccak(input + size, size, ctx[1]->state);

    const uint8_t* l0 = ctx[0]->memory;
    const uint8_t* l1 = ctx[1]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);

    VARIANT1_INIT(0);
    VARIANT1_INIT(1);
    VARIANT2_INIT(0);
    VARIANT2_INIT(1);
    VARIANT2_SET_ROUNDING_MODE();

    cn_explode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) h0, (__m128i*) l0);
    cn_explode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) h1, (__m128i*) l1);

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t al1 = h1[0] ^ h1[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    uint64_t ah1 = h1[1] ^ h1[5];

    __m128i bx00 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i bx01 = _mm_set_epi64x(h0[9] ^ h0[11], h0[8] ^ h0[10]);
    __m128i bx10 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
    __m128i bx11 = _mm_set_epi64x(h1[9] ^ h1[11], h1[8] ^ h1[10]);

    uint64_t idx0 = al0;
    uint64_t idx1 = al1;

    for (size_t i = 0; i < ITERATIONS; i++) {
        __m128i cx0, cx1;
        if (VARIANT == xmrig::VARIANT_TUBE || !SOFT_AES) {
            cx0 = _mm_load_si128((__m128i *) &l0[idx0 & MASK]);
            cx1 = _mm_load_si128((__m128i *) &l1[idx1 & MASK]);
        }

        const __m128i ax0 = _mm_set_epi64x(ah0, al0);
        const __m128i ax1 = _mm_set_epi64x(ah1, al1);
        if (VARIANT == xmrig::VARIANT_TUBE) {
            cx0 = aes_round_tweak_div(cx0, ax0);
            cx1 = aes_round_tweak_div(cx1, ax1);
        }
        else if (SOFT_AES) {
            cx0 = soft_aesenc((uint32_t*)&l0[idx0 & MASK], ax0);
            cx1 = soft_aesenc((uint32_t*)&l1[idx1 & MASK], ax1);
        }
        else {
            cx0 = _mm_aesenc_si128(cx0, ax0);
            cx1 = _mm_aesenc_si128(cx1, ax1);
        }

        if (IS_V1 || (VARIANT == xmrig::VARIANT_2)) {
            cryptonight_monero_tweak<VARIANT>((uint64_t*)&l0[idx0 & MASK], l0, idx0 & MASK, ax0, bx00, bx01, cx0);
            cryptonight_monero_tweak<VARIANT>((uint64_t*)&l1[idx1 & MASK], l1, idx1 & MASK, ax1, bx10, bx11, cx1);
        } else {
            _mm_store_si128((__m128i *) &l0[idx0 & MASK], _mm_xor_si128(bx00, cx0));
            _mm_store_si128((__m128i *) &l1[idx1 & MASK], _mm_xor_si128(bx10, cx1));
        }

        idx0 = _mm_cvtsi128_si64(cx0);
        idx1 = _mm_cvtsi128_si64(cx1);

        uint64_t hi0, lo0, hi1, lo1, cl0, ch0, cl1, ch1;
        cl0 = ((uint64_t*) &l0[idx0 & MASK])[0];
        ch0 = ((uint64_t*) &l0[idx0 & MASK])[1];
        cl1 = ((uint64_t*) &l1[idx1 & MASK])[0];
        ch1 = ((uint64_t*) &l1[idx1 & MASK])[1];

        if (VARIANT == xmrig::VARIANT_2) {
            VARIANT2_INTEGER_MATH_DUAL(0, cl0, cx0, 1, cl1, cx1);
            lo0 = __umul128(idx0, cl0, &hi0);
            lo1 = __umul128(idx1, cl1, &hi1);
            VARIANT2_SHUFFLE2(l0, idx0 & MASK, ax0, bx00, bx01, hi0, lo0);
            VARIANT2_SHUFFLE2(l1, idx1 & MASK, ax1, bx10, bx11, hi1, lo1);
        } else {
            lo0 = __umul128(idx0, cl0, &hi0);
            lo1 = __umul128(idx1, cl1, &hi1);
        }

        al0 += hi0;
        ah0 += lo0;

        ((uint64_t*)&l0[idx0 & MASK])[0] = al0;

        if (IS_V1 && (VARIANT == xmrig::VARIANT_TUBE || VARIANT == xmrig::VARIANT_RTO)) {
            ((uint64_t*) &l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0 ^ al0;
        } else if (IS_V1) {
            ((uint64_t*) &l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0;
        } else {
            ((uint64_t*) &l0[idx0 & MASK])[1] = ah0;
        }

        al0 ^= cl0;
        ah0 ^= ch0;
        idx0 = al0;

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            int64_t n = ((int64_t*)&l0[idx0 & MASK])[0];
            int32_t d = ((int32_t*)&l0[idx0 & MASK])[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)&l0[idx0 & MASK])[0] = n ^ q;

            if (VARIANT == xmrig::VARIANT_XHV) {
                d = ~d;
            }

            idx0 = d ^ q;
        }

        al1 += hi1;
        ah1 += lo1;

        ((uint64_t*)&l1[idx1 & MASK])[0] = al1;

        if (IS_V1 && (VARIANT == xmrig::VARIANT_TUBE || VARIANT == xmrig::VARIANT_RTO)) {
            ((uint64_t*)&l1[idx1 & MASK])[1] = ah1 ^ tweak1_2_1 ^ al1;
        } else if (IS_V1) {
            ((uint64_t*)&l1[idx1 & MASK])[1] = ah1 ^ tweak1_2_1;
        } else {
            ((uint64_t*)&l1[idx1 & MASK])[1] = ah1;
        }

        al1 ^= cl1;
        ah1 ^= ch1;
        idx1 = al1;

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            int64_t n = ((int64_t*)&l1[idx1 & MASK])[0];
            int32_t d = ((int32_t*)&l1[idx1 & MASK])[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)&l1[idx1 & MASK])[0] = n ^ q;

            if (VARIANT == xmrig::VARIANT_XHV) {
                d = ~d;
            }

            idx1 = d ^ q;
        }

        if (VARIANT == xmrig::VARIANT_2) {
            bx01 = bx00;
            bx11 = bx10;
        }
        bx00 = cx0;
        bx10 = cx1;
    }

    cn_implode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) l0, (__m128i*) h0);
    cn_implode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) l1, (__m128i*) h1);

    xmrig::keccakf(h0, 24);
    xmrig::keccakf(h1, 24);

    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
    extra_hashes[ctx[1]->state[0] & 3](ctx[1]->state, 200, output + 32);
}


#define CN_STEP1(a, b0, b1, c, l, ptr, idx)           \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    c = _mm_load_si128(ptr);


#define CN_STEP2(a, b0, b1, c, l, ptr, idx)                            \
    if (VARIANT == xmrig::VARIANT_TUBE) {                              \
        c = aes_round_tweak_div(c, a);                                 \
    }                                                                  \
    else if (SOFT_AES) {                                               \
        c = soft_aesenc(c, a);                                         \
    } else {                                                           \
        c = _mm_aesenc_si128(c, a);                                    \
    }                                                                  \
                                                                       \
    if (IS_V1 || (VARIANT == xmrig::VARIANT_2)) {                      \
        cryptonight_monero_tweak<VARIANT>((uint64_t*)ptr, l, idx & MASK, a, b0, b1, c); \
    } else {                                                           \
        _mm_store_si128(ptr, _mm_xor_si128(b0, c));                    \
    }


#define CN_STEP3(part, a, b0, b1, c, l, ptr, idx)     \
    idx = _mm_cvtsi128_si64(c);                       \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    uint64_t cl##part = ((uint64_t*)ptr)[0];          \
    uint64_t ch##part = ((uint64_t*)ptr)[1];


#define CN_STEP4(part, a, b0, b1, c, l, mc, ptr, idx)   \
    if (VARIANT == xmrig::VARIANT_2) {                  \
        VARIANT2_INTEGER_MATH(part, cl##part, c);       \
        lo = __umul128(idx, cl##part, &hi);             \
        VARIANT2_SHUFFLE2(l, idx & MASK, a, b0, b1, hi, lo); \
    } else {                                            \
        lo = __umul128(idx, cl##part, &hi);             \
    }                                                   \
    a = _mm_add_epi64(a, _mm_set_epi64x(lo, hi));       \
                                                        \
    if (IS_V1) {                                        \
        _mm_store_si128(ptr, _mm_xor_si128(a, mc));     \
                                                        \
        if (VARIANT == xmrig::VARIANT_TUBE ||           \
            VARIANT == xmrig::VARIANT_RTO) {            \
            ((uint64_t*)ptr)[1] ^= ((uint64_t*)ptr)[0]; \
        }                                               \
    } else {                                            \
        _mm_store_si128(ptr, a);                        \
    }                                                   \
                                                        \
    a = _mm_xor_si128(a, _mm_set_epi64x(ch##part, cl##part)); \
    idx = _mm_cvtsi128_si64(a);                         \
                                                        \
    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {             \
        int64_t n = ((int64_t*)&l[idx & MASK])[0];      \
        int32_t d = ((int32_t*)&l[idx & MASK])[2];      \
        int64_t q = n / (d | 0x5);                      \
        ((int64_t*)&l[idx & MASK])[0] = n ^ q;          \
        if (VARIANT == xmrig::VARIANT_XHV) {            \
            d = ~d;                                     \
        }                                               \
                                                        \
        idx = d ^ q;                                    \
    }                                                   \
    if (VARIANT == xmrig::VARIANT_2) {                  \
        b1 = b0;                                        \
    }                                                   \
    b0 = c;


#define CONST_INIT(ctx, n)                                                                       \
    __m128i mc##n;                                                                               \
    __m128i division_result_xmm_##n;                                                             \
    __m128i sqrt_result_xmm_##n;                                                                 \
    if (IS_V1) {                                                                                 \
        mc##n = _mm_set_epi64x(*reinterpret_cast<const uint64_t*>(input + n * size + 35) ^       \
                               *(reinterpret_cast<const uint64_t*>((ctx)->state) + 24), 0);      \
    }                                                                                            \
    if (VARIANT == xmrig::VARIANT_2) {                                                           \
        division_result_xmm_##n = _mm_cvtsi64_si128(h##n[12]);                                   \
        sqrt_result_xmm_##n = _mm_cvtsi64_si128(h##n[13]);                                       \
    }                                                                                            \
    __m128i ax##n = _mm_set_epi64x(h##n[1] ^ h##n[5], h##n[0] ^ h##n[4]);                        \
    __m128i bx##n##0 = _mm_set_epi64x(h##n[3] ^ h##n[7], h##n[2] ^ h##n[6]);                     \
    __m128i bx##n##1 = _mm_set_epi64x(h##n[9] ^ h##n[11], h##n[8] ^ h##n[10]);                   \
    __m128i cx##n = _mm_setzero_si128();


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_triple_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_V1        = xmrig::cn_base_variant<VARIANT>() == xmrig::VARIANT_1;

    if (IS_V1 && size < 43) {
        memset(output, 0, 32 * 3);
        return;
    }

    for (size_t i = 0; i < 3; i++) {
        xmrig::keccak(input + size * i, size, ctx[i]->state);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    VARIANT2_SET_ROUNDING_MODE();

    uint64_t idx0, idx1, idx2;
    idx0 = _mm_cvtsi128_si64(ax0);
    idx1 = _mm_cvtsi128_si64(ax1);
    idx2 = _mm_cvtsi128_si64(ax2);

    for (size_t i = 0; i < ITERATIONS; i++) {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2;

        CN_STEP1(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx20, bx21, cx2, l2, ptr2, idx2);

        CN_STEP2(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx20, bx21, cx2, l2, ptr2, idx2);

        CN_STEP3(0, ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP3(1, ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP3(2, ax2, bx20, bx21, cx2, l2, ptr2, idx2);

        CN_STEP4(0, ax0, bx00, bx01, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(1, ax1, bx10, bx11, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(2, ax2, bx20, bx21, cx2, l2, mc2, ptr2, idx2);
    }

    for (size_t i = 0; i < 3; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        xmrig::keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_quad_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_V1        = xmrig::cn_base_variant<VARIANT>() == xmrig::VARIANT_1;;

    if (IS_V1 && size < 43) {
        memset(output, 0, 32 * 4);
        return;
    }

    for (size_t i = 0; i < 4; i++) {
        xmrig::keccak(input + size * i, size, ctx[i]->state);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint8_t* l3  = ctx[3]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    CONST_INIT(ctx[3], 3);
    VARIANT2_SET_ROUNDING_MODE();

    uint64_t idx0, idx1, idx2, idx3;
    idx0 = _mm_cvtsi128_si64(ax0);
    idx1 = _mm_cvtsi128_si64(ax1);
    idx2 = _mm_cvtsi128_si64(ax2);
    idx3 = _mm_cvtsi128_si64(ax3);

    for (size_t i = 0; i < ITERATIONS; i++)
    {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2, *ptr3;

        CN_STEP1(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP1(ax3, bx30, bx31, cx3, l3, ptr3, idx3);

        CN_STEP2(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP2(ax3, bx30, bx31, cx3, l3, ptr3, idx3);

        CN_STEP3(0, ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP3(1, ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP3(2, ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP3(3, ax3, bx30, bx31, cx3, l3, ptr3, idx3);

        CN_STEP4(0, ax0, bx00, bx01, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(1, ax1, bx10, bx11, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(2, ax2, bx20, bx21, cx2, l2, mc2, ptr2, idx2);
        CN_STEP4(3, ax3, bx30, bx31, cx3, l3, mc3, ptr3, idx3);
    }

    for (size_t i = 0; i < 4; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        xmrig::keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_penta_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO, VARIANT>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    constexpr bool IS_V1        = xmrig::cn_base_variant<VARIANT>() == xmrig::VARIANT_1;

    if (IS_V1 && size < 43) {
        memset(output, 0, 32 * 5);
        return;
    }

    for (size_t i = 0; i < 5; i++) {
        xmrig::keccak(input + size * i, size, ctx[i]->state);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint8_t* l3  = ctx[3]->memory;
    uint8_t* l4  = ctx[4]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);
    uint64_t* h4 = reinterpret_cast<uint64_t*>(ctx[4]->state);

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    CONST_INIT(ctx[3], 3);
    CONST_INIT(ctx[4], 4);
    VARIANT2_SET_ROUNDING_MODE();

    uint64_t idx0, idx1, idx2, idx3, idx4;
    idx0 = _mm_cvtsi128_si64(ax0);
    idx1 = _mm_cvtsi128_si64(ax1);
    idx2 = _mm_cvtsi128_si64(ax2);
    idx3 = _mm_cvtsi128_si64(ax3);
    idx4 = _mm_cvtsi128_si64(ax4);

    for (size_t i = 0; i < ITERATIONS; i++)
    {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2, *ptr3, *ptr4;

        CN_STEP1(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP1(ax3, bx30, bx31, cx3, l3, ptr3, idx3);
        CN_STEP1(ax4, bx40, bx41, cx4, l4, ptr4, idx4);

        CN_STEP2(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP2(ax3, bx30, bx31, cx3, l3, ptr3, idx3);
        CN_STEP2(ax4, bx40, bx41, cx4, l4, ptr4, idx4);

        CN_STEP3(0, ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP3(1, ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP3(2, ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP3(3, ax3, bx30, bx31, cx3, l3, ptr3, idx3);
        CN_STEP3(4, ax4, bx40, bx41, cx4, l4, ptr4, idx4);

        CN_STEP4(0, ax0, bx00, bx01, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(1, ax1, bx10, bx11, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(2, ax2, bx20, bx21, cx2, l2, mc2, ptr2, idx2);
        CN_STEP4(3, ax3, bx30, bx31, cx3, l3, mc3, ptr3, idx3);
        CN_STEP4(4, ax4, bx40, bx41, cx4, l4, mc4, ptr4, idx4);
    }

    for (size_t i = 0; i < 5; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        xmrig::keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}

#endif /* __CRYPTONIGHT_PPC64_H__ */
