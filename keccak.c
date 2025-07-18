// PERFORMANCE NOTES
// - This file supports SIMD-accelerated (AVX2/NEON) Keccak/SHA3/SHAKE256 hashing for batch public keys.
// - All input/output buffers must be 32-byte aligned for AVX2.
// - SIMD plug-in points are clearly marked for future hand-written vector code.

#include "keccak.h"
#include "keccak_avx2.h"
#include <immintrin.h> // For AVX2 intrinsics (if available)
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define FOR(i,n) for(i=0; i<n; ++i)
typedef u32 ui;

static int LFSR86540(u8 *R) { (*R)=((*R)<<1)^(((*R)&0x80)?0x71:0); return ((*R)&2)>>1; }
#define ROL(a,o) ((((u64)a)<<o)^(((u64)a)>>(64-o)))
static u64 load64(const u8 *x) { ui i; u64 u=0; FOR(i,8) { u<<=8; u|=x[7-i]; } return u; }
static void store64(u8 *x, u64 u) { ui i; FOR(i,8) { x[i]=u; u>>=8; } }
static void xor64(u8 *x, u64 u) { ui i; FOR(i,8) { x[i]^=u; u>>=8; } }
#define rL(x,y) load64((u8*)s+8*(x+5*y))
#define wL(x,y,l) store64((u8*)s+8*(x+5*y),l)
#define XL(x,y,l) xor64((u8*)s+8*(x+5*y),l)
static void KeccakF1600(void *s)
{
    ui r,x,y,i,j,Y; u8 R=0x01; u64 C[5],D;
    for(i=0; i<24; i++) {
        /*θ*/ FOR(x,5) C[x]=rL(x,0)^rL(x,1)^rL(x,2)^rL(x,3)^rL(x,4); FOR(x,5) { D=C[(x+4)%5]^ROL(C[(x+1)%5],1); FOR(y,5) XL(x,y,D); }
        /*ρπ*/ x=1; y=r=0; D=rL(x,y); FOR(j,24) { r+=j+1; Y=(2*x+3*y)%5; x=y; y=Y; C[0]=rL(x,y); wL(x,y,ROL(D,r%64)); D=C[0]; }
        /*χ*/ FOR(y,5) { FOR(x,5) C[x]=rL(x,y); FOR(x,5) wL(x,y,C[x]^((~C[(x+1)%5])&C[(x+2)%5])); }
        /*ι*/ FOR(j,7) if (LFSR86540(&R)) XL(0,0,(u64)1<<((1<<j)-1));
    }
}
void Keccak(u32 r, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen)
{
    /*initialize*/ u8 s[200]; ui R=r/8; ui i,b=0; FOR(i,200) s[i]=0;
    /*absorb*/ while(inLen>0) { b=(inLen<R)?inLen:R; FOR(i,b) s[i]^=in[i]; in+=b; inLen-=b; if (b==R) { KeccakF1600(s); b=0; } }
    /*pad*/ s[b]^=sfx; if((sfx&0x80)&&(b==(R-1))) KeccakF1600(s); s[R-1]^=0x80; KeccakF1600(s);
    /*squeeze*/ while(outLen>0) { b=(outLen<R)?outLen:R; FOR(i,b) out[i]=s[i]; out+=b; outLen-=b; if(outLen>0) KeccakF1600(s); }
}

// Batch Keccak hash interface implementation
void Keccak_bulk(u32 r, const u8 **in, const u64 *inLen, u8 sfx, u8 **out, const u64 *outLen, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        Keccak(r, in[i], inLen[i], sfx, out[i], outLen[i]);
    }
}

// SIMD stub: AVX2-accelerated batch Keccak hashing
void avx2_keccak_bulk(u32 r, const u8 **in, const u64 *inLen, u8 sfx, u8 **out, const u64 *outLen, size_t n) {
#ifdef __AVX2__
    const size_t block = 4;
    size_t i = 0;
    for (; i + block - 1 < n; i += block) {
        // Batch call AVX2 SIMD Keccak core (SHA3-256 example)
        const uint8_t *in4[4]   = { in[i+0], in[i+1], in[i+2], in[i+3] };
        size_t inlen4[4]        = { inLen[i+0], inLen[i+1], inLen[i+2], inLen[i+3] };
        uint8_t *out4[4]        = { out[i+0], out[i+1], out[i+2], out[i+3] };
        sha3_256x4_avx2(in4, inlen4, out4);
    }
    // Handle remaining inputs less than 4
    for (; i < n; ++i) {
        Keccak(r, in[i], inLen[i], sfx, out[i], outLen[i]);
    }
#else
    for (size_t i = 0; i < n; ++i) {
        Keccak(r, in[i], inLen[i], sfx, out[i], outLen[i]);
    }
#endif
}

// SIMD plug-in point: call avx2_keccak_bulk if available, else fallback
