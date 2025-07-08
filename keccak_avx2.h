#ifndef KECCAK_AVX2_H
#define KECCAK_AVX2_H
#include <stdint.h>
#include <stddef.h>

// 批量AVX2 Keccak（SHA3-256）接口，单次处理4组输入
// in: 4个输入指针，inlen: 4个输入长度，out: 4个输出指针
void sha3_256x4_avx2(const uint8_t *in[4], size_t inlen[4], uint8_t *out[4]);

#endif // KECCAK_AVX2_H 