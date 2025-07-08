
void Keccak(u32 r, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen);

#define FIPS202_SHA3_224_LEN 28
#define FIPS202_SHA3_256_LEN 32
#define FIPS202_SHA3_384_LEN 48
#define FIPS202_SHA3_512_LEN 64

static inline void FIPS202_SHAKE128(const u8 *in, u64 inLen, u8 *out, u64 outLen) { Keccak(1344, in, inLen, 0x1F, out, outLen); }
static inline void FIPS202_SHAKE256(const u8 *in, u64 inLen, u8 *out, u64 outLen) { Keccak(1088, in, inLen, 0x1F, out, outLen); }
static inline void FIPS202_SHA3_224(const u8 *in, u64 inLen, u8 *out) { Keccak(1152, in, inLen, 0x06, out, 28); }
static inline void FIPS202_SHA3_256(const u8 *in, u64 inLen, u8 *out) { Keccak(1088, in, inLen, 0x06, out, 32); }
static inline void FIPS202_SHA3_384(const u8 *in, u64 inLen, u8 *out) { Keccak(832, in, inLen, 0x06, out, 48); }
static inline void FIPS202_SHA3_512(const u8 *in, u64 inLen, u8 *out) { Keccak(576, in, inLen, 0x06, out, 64); }

// 批量Keccak哈希接口声明
void Keccak_bulk(u32 r, const u8 **in, const u64 *inLen, u8 sfx, u8 **out, const u64 *outLen, size_t n);
static inline void FIPS202_SHAKE256_bulk(const u8 **in, const u64 *inLen, u8 **out, const u64 *outLen, size_t n) { Keccak_bulk(1088, in, inLen, 0x1F, out, outLen, n); }
