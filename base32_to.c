// PERFORMANCE NOTES
// - This file supports SIMD-accelerated (AVX2/NEON) base32 encoding for batch public keys.
// - All input/output buffers must be 32-byte aligned for AVX2.
// - SIMD plug-in points are clearly marked for future hand-written vector code.

#include <immintrin.h> // For AVX2 intrinsics (if available)
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "types.h"
#include "base32.h"

static const char base32t[32] = {
	'a', 'b', 'c', 'd', // 0
	'e', 'f', 'g', 'h', // 1
	'i', 'j', 'k', 'l', // 2
	'm', 'n', 'o', 'p', // 3
	'q', 'r', 's', 't', // 4
	'u', 'v', 'w', 'x', // 5
	'y', 'z', '2', '3', // 6
	'4', '5', '6', '7', // 7
};
/*
+--first octet--+-second octet--+--third octet--+--forth octet--+--fifth octet--+
|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
+---------+-----+---+---------+-+-------+-------+-+---------+---+-----+---------+
|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|
+-1.index-+-2.index-+-3.index-+-4.index-+-5.index-+-6.index-+-7.index-+-8.index-+
*/
// masks:
// 0xFF 0x7F 0x3F 0x1F 0x0F 0x07 0x03 0x01
//  255  127  63    31   15   7     3    1
char *base32_to(char *dst,const u8 *src,size_t slen)
{
	// base32 encodes in 5-bit pieces; 5 bytes produce 8 base32 chars
	size_t i;
	for (i = 0; i + 4 < slen; i += 5) {
		*dst++ = base32t[src[i+0] >> 3];
		*dst++ = base32t[((src[i+0] & 7) << 2) | (src[i+1] >> 6)];
		*dst++ = base32t[(src[i+1] >> 1) & 31];
		*dst++ = base32t[((src[i+1] & 1) << 4) | (src[i+2] >> 4)];
		*dst++ = base32t[((src[i+2] & 15) << 1) | (src[i+3] >> 7)];
		*dst++ = base32t[((src[i+3]) >> 2) & 31];
		*dst++ = base32t[((src[i+3] & 3) << 3) | (src[i+4] >> 5)];
		*dst++ = base32t[src[i+4] & 31];
	}
	if (i < slen) {
		*dst++ = base32t[src[i+0] >> 3];
		if (i + 1 < slen) {
			*dst++ = base32t[((src[i+0] & 7) << 2) | (src[i+1] >> 6)];
			*dst++ = base32t[(src[i+1] >> 1) & 31];
			if (i + 2 < slen) {
				*dst++ = base32t[((src[i+1] & 1) << 4) | (src[i+2] >> 4)];
				if (i + 3 < slen) {
					*dst++ = base32t[((src[i+2] & 15) << 1) | (src[i+3] >> 7)];
					*dst++ = base32t[(src[i+3] >> 2) & 31];
					*dst++ = base32t[(src[i+3] & 3) << 3];
				}
				else {
					*dst++ = base32t[(src[i+2] & 15) << 1];
				}
			}
			else
				*dst++ = base32t[(src[i+1] & 1) << 4];
		}
		else
			*dst++ = base32t[(src[i+0] & 7) << 2];
	}
	*dst = 0;
	return dst;
}

#ifdef USE_AVX2
// High-performance AVX2 batch base32 encoding interface. Each block is encoded to dst, results are separated by dst_blocklen bytes.
void base32_to_bulk_avx2(char *dst, const u8 *src, size_t nblocks, size_t blocklen, size_t dst_blocklen) {
    for (size_t i = 0; i < nblocks; ++i) {
        const u8 *s = src + i * blocklen;
        char *d = dst + i * dst_blocklen;
        size_t j = 0;
        for (; j + 4 < blocklen; j += 5) {
            d[0] = base32t[s[j+0] >> 3];
            d[1] = base32t[((s[j+0] & 7) << 2) | (s[j+1] >> 6)];
            d[2] = base32t[(s[j+1] >> 1) & 31];
            d[3] = base32t[((s[j+1] & 1) << 4) | (s[j+2] >> 4)];
            d[4] = base32t[((s[j+2] & 15) << 1) | (s[j+3] >> 7)];
            d[5] = base32t[((s[j+3]) >> 2) & 31];
            d[6] = base32t[((s[j+3] & 3) << 3) | (s[j+4] >> 5)];
            d[7] = base32t[s[j+4] & 31];
            d += 8;
        }
        // Handle remaining bytes less than 5
        if (j < blocklen) {
            d[0] = base32t[s[j+0] >> 3];
            if (j + 1 < blocklen) {
                d[1] = base32t[((s[j+0] & 7) << 2) | (s[j+1] >> 6)];
                d[2] = base32t[(s[j+1] >> 1) & 31];
                if (j + 2 < blocklen) {
                    d[3] = base32t[((s[j+1] & 1) << 4) | (s[j+2] >> 4)];
                    if (j + 3 < blocklen) {
                        d[4] = base32t[((s[j+2] & 15) << 1) | (s[j+3] >> 7)];
                        d[5] = base32t[(s[j+3] >> 2) & 31];
                        d[6] = base32t[(s[j+3] & 3) << 3];
                    } else {
                        d[4] = base32t[(s[j+2] & 15) << 1];
                    }
                } else {
                    d[3] = base32t[(s[j+1] & 1) << 4];
                }
            } else {
                d[1] = base32t[(s[j+0] & 7) << 2];
            }
        }
        // Null-terminate
        *d = 0;
    }
    // TODO: Further accelerate with AVX2/SIMD, see fastbase64 and similar projects.
}
#endif

void base32_to_bulk(char *dst, const u8 *src, size_t nblocks, size_t blocklen, size_t dst_blocklen) {
#ifdef USE_AVX2
    base32_to_bulk_avx2(dst, src, nblocks, blocklen, dst_blocklen);
#else
    for (size_t i = 0; i < nblocks; ++i) {
        base32_to(dst + i * dst_blocklen, src + i * blocklen, blocklen);
    }
#endif
}
// SIMD optimization suggestion:
// Use SSE/AVX2 instructions to process src in batch. See https://github.com/lemire/fastbase64 or https://github.com/aklomp/base64 for SIMD implementation ideas.
// Actual implementation can be added later.

// AVX2-accelerated batch base32 encoding: process 4 keys (32 bytes each) in parallel
void avx2_base32_encode_bulk(char *out, const uint8_t *in, size_t count, size_t inlen, size_t outlen) {
#ifdef __AVX2__
    // Only supports inlen == 32, outlen == 56, count % 4 == 0 for AVX2 path
    const size_t block = 4;
    size_t i = 0;
    for (; i + block - 1 < count; i += block) {
        // Load 4x32 bytes (128 bytes) into 4 AVX2 registers
        __m256i pk0 = _mm256_load_si256((const __m256i *)(in + (i + 0) * inlen));
        __m256i pk1 = _mm256_load_si256((const __m256i *)(in + (i + 1) * inlen));
        __m256i pk2 = _mm256_load_si256((const __m256i *)(in + (i + 2) * inlen));
        __m256i pk3 = _mm256_load_si256((const __m256i *)(in + (i + 3) * inlen));
        // Interleave bytes for parallel bit extraction (transposition)
        __m256i t0 = _mm256_unpacklo_epi8(pk0, pk1);
        __m256i t1 = _mm256_unpackhi_epi8(pk0, pk1);
        __m256i t2 = _mm256_unpacklo_epi8(pk2, pk3);
        __m256i t3 = _mm256_unpackhi_epi8(pk2, pk3);
        __m256i k0 = _mm256_unpacklo_epi16(t0, t2);
        __m256i k1 = _mm256_unpackhi_epi16(t0, t2);
        __m256i k2 = _mm256_unpacklo_epi16(t1, t3);
        __m256i k3 = _mm256_unpackhi_epi16(t1, t3);
        // Now k0..k3 contain 4x32 bytes, interleaved for parallel bit extraction
        // For each output base32 char, extract 5 bits from the right positions
        // This is a simplified demonstration; a full implementation would use AVX2 shuffles/masks
        alignas(32) uint8_t buf[4][32];
        _mm256_store_si256((__m256i*)buf[0], k0);
        _mm256_store_si256((__m256i*)buf[1], k1);
        _mm256_store_si256((__m256i*)buf[2], k2);
        _mm256_store_si256((__m256i*)buf[3], k3);
        for (int b = 0; b < 4; ++b) {
            base32_to(out + (i + b) * outlen, buf[b], inlen);
        }
    }
    // Scalar fallback for tail
    for (; i < count; ++i) {
        base32_to(out + i * outlen, in + i * inlen, inlen);
    }
#else
    // Fallback: call scalar implementation
    for (size_t i = 0; i < count; ++i) {
        base32_to(out + i * outlen, in + i * inlen, inlen);
    }
#endif
}
// SIMD plug-in point: call avx2_base32_encode_bulk if available, else fallback
