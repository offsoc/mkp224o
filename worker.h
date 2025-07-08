// PERFORMANCE NOTES
// - struct statstruct is padded to 64 bytes to avoid false sharing between threads.
// - All batch buffers are 32-byte aligned for SIMD and cache efficiency.
// - All statistics are per-thread and merged in the main thread to avoid contention.

extern pthread_mutex_t keysgenerated_mutex;
extern volatile size_t keysgenerated;
extern volatile int endwork;

extern int yamloutput;
extern int yamlraw;
extern int numwords;
extern size_t numneedgenerate;

extern char *workdir;
extern size_t workdirlen;

#ifdef STATISTICS
// Per-thread statistics structure, padded to avoid false sharing
struct statstruct {
    union {
        u32 v;
        size_t align;
    } numcalc;
    union {
        u32 v;
        size_t align;
    } numsuccess;
    union {
        u32 v;
        size_t align;
    } numrestart;
    char _pad[64 - (3 * sizeof(size_t))]; // Explicit cacheline padding
};
VEC_STRUCT(statsvec,struct statstruct);
#endif

#ifdef PASSPHRASE
extern pthread_mutex_t determseed_mutex;
extern u8 determseed[SEED_LEN];
extern int pw_skipnear;
extern int pw_warnnear;
#endif

extern void worker_init(void);

extern char *makesname(void);
extern size_t worker_batch_memuse(void);

extern void *CRYPTO_NAMESPACE(worker_batch)(void *task);
#ifdef PASSPHRASE
extern void *CRYPTO_NAMESPACE(worker_batch_pass)(void *task);
#endif
