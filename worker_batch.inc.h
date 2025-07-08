
// PERFORMANCE NOTES
// - All batch buffers are 32-byte aligned for AVX2 SIMD (future-proof for AVX512).
// - Batch main loop is designed for vectorization (see SIMD ENTRY POINT comments).
// - Per-thread stats should be padded to avoid false sharing (see struct statstruct).
// - For NUMA/affinity, see TODO comments in worker launch (main.c).
// - Memory layout is contiguous for cache efficiency.

// Structure holding all batch buffers for high-throughput keygen/encoding/filtering
struct batch_buffers {
    ge_p3 *ge_batch;        // 32-byte aligned, SIMD-friendly
    fe *tmp_batch;          // 32-byte aligned
    bytes32 *pk_batch;      // 32-byte aligned
    char (*sname)[64];      // Output names
    const char **onion_ptrs;// Pointers to output names
    int *filter_results;    // Filter results
    u8 (*hashsrc_b)[64];    // Hash input buffers
    u8 **hashsrc_bulk;      // Hash input pointers
    u64 *hashsrc_len_bulk;  // Hash input lengths
    u8 **pk_bulk;           // Output pubkey pointers
    u64 *pk_outlen_bulk;    // Output pubkey lengths
};

// Allocate all batch buffers for a given batch size, with proper alignment for SIMD
static struct batch_buffers *alloc_batch_buffers(size_t batchnum) {
    struct batch_buffers *bufs = calloc(1, sizeof(*bufs));
    if (!bufs) return NULL;
    bufs->ge_batch = aligned_alloc(32, sizeof(ge_p3) * batchnum);
    bufs->tmp_batch = aligned_alloc(32, sizeof(fe) * batchnum);
    bufs->pk_batch = aligned_alloc(32, sizeof(bytes32) * batchnum);
    bufs->sname = calloc(batchnum, 64);
    bufs->onion_ptrs = calloc(batchnum, sizeof(char*));
    bufs->filter_results = calloc(batchnum, sizeof(int));
    bufs->hashsrc_b = calloc(batchnum, 64);
    bufs->hashsrc_bulk = calloc(batchnum, sizeof(u8*));
    bufs->hashsrc_len_bulk = calloc(batchnum, sizeof(u64));
    bufs->pk_bulk = calloc(batchnum, sizeof(u8*));
    bufs->pk_outlen_bulk = calloc(batchnum, sizeof(u64));
    if (!bufs->ge_batch || !bufs->tmp_batch || !bufs->pk_batch || !bufs->sname || !bufs->onion_ptrs || !bufs->filter_results || !bufs->hashsrc_b || !bufs->hashsrc_bulk || !bufs->hashsrc_len_bulk || !bufs->pk_bulk || !bufs->pk_outlen_bulk) {
        free(bufs->ge_batch); free(bufs->tmp_batch); free(bufs->pk_batch); free(bufs->sname); free(bufs->onion_ptrs); free(bufs->filter_results); free(bufs->hashsrc_b); free(bufs->hashsrc_bulk); free(bufs->hashsrc_len_bulk); free(bufs->pk_bulk); free(bufs->pk_outlen_bulk); free(bufs);
        return NULL;
    }
    return bufs;
}

// Free all batch buffers
static void free_batch_buffers(struct batch_buffers *bufs) {
    if (!bufs) return;
    free(bufs->ge_batch); free(bufs->tmp_batch); free(bufs->pk_batch); free(bufs->sname); free(bufs->onion_ptrs); free(bufs->filter_results); free(bufs->hashsrc_b); free(bufs->hashsrc_bulk); free(bufs->hashsrc_len_bulk); free(bufs->pk_bulk); free(bufs->pk_outlen_bulk); free(bufs);
}

// High-performance batch worker: generates, encodes, filters, and hashes keys in bulk
// If task is a batch_buffers pointer, uses external buffers (main process); otherwise allocates internally (sampling)
void *CRYPTO_NAMESPACE(worker_batch)(void *task) {
    struct batch_buffers *bufs = NULL;
    int need_free = 0;
    if (task && ((uintptr_t)task % sizeof(void *) == 0)) {
        bufs = (struct batch_buffers *)task;
    } else {
        size_t batchnum = BATCHNUM;
        bufs = alloc_batch_buffers(batchnum);
        need_free = 1;
        if (!bufs) return NULL;
    }

    size_t counter;
    size_t i;

#ifdef STATISTICS
	struct statstruct *st = (struct statstruct *)task;
#else
	(void) task;
#endif

	PREFILTER

	memcpy(secret,skprefix,SKPREFIX_SIZE);
	wpk[PUBLIC_LEN] = 0;
	memset(&pubonion,0,sizeof(pubonion));
	memcpy(pubonion.raw,pkprefix,PKPREFIX_SIZE);
	// write version later as it will be overwritten by hash
	memcpy(hashsrc,checksumstr,checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	// 批量分配sname缓冲区，最大长度64
	// char sname[BATCHNUM][64]; // This line is removed as sname is now a member of batch_buffers

initseed:

#ifdef STATISTICS
	++st->numrestart.v;
#endif

	randombytes(seed,sizeof(seed));

	ed25519_seckey_expand(sk,seed);

	ge_scalarmult_base(&ge_public,sk);

	for (counter = 0;counter < SIZE_MAX-(8*BATCHNUM);counter += 8*BATCHNUM) {
		ge_p1p1 ALIGN(16) sum;

		if (unlikely(endwork))
			goto end;


		for (size_t b = 0;b < BATCHNUM;++b) {
			bufs->ge_batch[b] = ge_public;
			ge_add(&sum,&ge_public,&ge_eightpoint);
			ge_p1p1_to_p3(&ge_public,&sum);
		}
		// NOTE: leaves unfinished one bit at the very end
		ge_p3_batchtobytes_destructive_1(bufs->pk_batch,bufs->ge_batch,bufs->tmp_batch,BATCHNUM);

#ifdef STATISTICS
		st->numcalc.v += BATCHNUM;
#endif

		// 批量base32编码
		// SIMD plug-in point: batch base32 encoding
#ifdef __AVX2__
    avx2_base32_encode_bulk((char *)base32buf, (const uint8_t *)bufs->pk_batch, BATCHNUM, PUBONION_LEN, ONION_ADDRLEN);
#else
    base32_to_bulk((char *)base32buf, (const u8 *)bufs->pk_batch, BATCHNUM, PUBONION_LEN, ONION_ADDRLEN);
#endif

		// 批量筛选优化
		for (size_t b = 0; b < BATCHNUM; ++b) {
			bufs->onion_ptrs[b] = bufs->sname[b];
		}
#if defined(ENABLE_REGEX)
		filters_match_regex_bulk(bufs->onion_ptrs, bufs->filter_results, BATCHNUM);
#elif defined(ENABLE_GLOB)
		// SIMD plug-in point: batch filtering
#ifdef __AVX2__
    avx2_filters_match_glob_bulk(bufs->onion_ptrs, bufs->filter_results, BATCHNUM);
#else
    filters_match_glob_bulk(bufs->onion_ptrs, bufs->filter_results, BATCHNUM);
#endif
#else
		filters_match_bin_bulk(bufs->onion_ptrs, bufs->filter_results, BATCHNUM);
#endif
		for (size_t b = 0; b < BATCHNUM; ++b) {
			if (bufs->filter_results[b]) {
				if (filter_mode == 1) {
#ifdef PCRE2FILTER
					if (!filters_match_regex(base32buf[b]))
						continue;
					// found!
					ge_p3_batchtobytes_destructive_finish(bufs->pk_batch[b],&bufs->ge_batch[b]);
					memcpy(pk,bufs->pk_batch[b],PUBLIC_LEN);
					addsztoscalar32(sk,counter + (b * 8));
					if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
						goto initseed;
					ADDNUMSUCCESS;
					memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
					FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
					pk[PUBLIC_LEN + 2] = 0x03;
					snprintf(bufs->sname[b], 64, "%s.onion", base32buf[b]);
					onionready(bufs->sname[b],secret,pubonion.raw,0);
					pk[PUBLIC_LEN] = 0;
					goto initseed;
#endif
				} else if (filter_mode == 2) {
					if (!filters_match_glob(base32buf[b]))
						continue;
					// found!
					ge_p3_batchtobytes_destructive_finish(bufs->pk_batch[b],&bufs->ge_batch[b]);
					memcpy(pk,bufs->pk_batch[b],PUBLIC_LEN);
					addsztoscalar32(sk,counter + (b * 8));
					if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
						goto initseed;
					ADDNUMSUCCESS;
					memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
					FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
					pk[PUBLIC_LEN + 2] = 0x03;
					snprintf(bufs->sname[b], 64, "%s.onion", base32buf[b]);
					onionready(bufs->sname[b],secret,pubonion.raw,0);
					pk[PUBLIC_LEN] = 0;
					goto initseed;
				} else {
					DOFILTER(i,bufs->pk_batch[b],{
						if (numwords > 1) {
							shiftpk(wpk,bufs->pk_batch[b],filter_len(i));
							size_t j;
							for (int w = 1;;) {
								DOFILTER(j,wpk,goto secondfind);
								goto next;
							secondfind:
								if (++w >= numwords)
									break;
								shiftpk(wpk,wpk,filter_len(j));
							}
						}
						// found!
						// finish it up
						ge_p3_batchtobytes_destructive_finish(bufs->pk_batch[b],&bufs->ge_batch[b]);
						// copy public key
						memcpy(pk,bufs->pk_batch[b],PUBLIC_LEN);
						// update secret key with counter
						addsztoscalar32(sk,counter + (b * 8));
						// sanity check
						if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
							goto initseed;

						ADDNUMSUCCESS;

						// calc checksum
						memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
						FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
						// version byte
						pk[PUBLIC_LEN + 2] = 0x03;
						// full name
						snprintf(bufs->sname[b], 64, "%s.onion", base32buf[b]);
						onionready(bufs->sname[b],secret,pubonion.raw,0);
						pk[PUBLIC_LEN] = 0; // what is this for?
						// don't reuse same seed
						goto initseed;
					});
				}
			}
		next:
			;
		}
		// --- 批量公钥校验和哈希 ---
		for (size_t b = 0; b < BATCHNUM; ++b) {
			memcpy(bufs->hashsrc_b[b], checksumstr, checksumstrlen);
			memcpy(bufs->hashsrc_b[b] + checksumstrlen, bufs->pk_batch[b], PUBLIC_LEN);
			bufs->hashsrc_bulk[b] = bufs->hashsrc_b[b];
			bufs->hashsrc_len_bulk[b] = checksumstrlen + PUBLIC_LEN;
			bufs->pk_bulk[b] = &bufs->pk_batch[b][PUBLIC_LEN];
			bufs->pk_outlen_bulk[b] = 32;
		}
		// SIMD plug-in point: batch hashing
#ifdef __AVX2__
    avx2_keccak_bulk(136, (const u8 **)bufs->hashsrc_bulk, bufs->hashsrc_len_bulk, 0x1f, bufs->pk_bulk, bufs->pk_outlen_bulk, BATCHNUM);
#else
    Keccak_bulk(136, (const u8 **)bufs->hashsrc_bulk, bufs->hashsrc_len_bulk, 0x1f, bufs->pk_bulk, bufs->pk_outlen_bulk, BATCHNUM);
#endif
#ifdef STATISTICS
		double t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
		struct timespec tsample;
		nanosleep(&tsample, 0); // 预防未初始化警告
		double now() { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec/1e9; }
		t0 = now();
#endif
		// 密钥生成
		for (size_t b = 0;b < BATCHNUM;++b) {
			bufs->ge_batch[b] = ge_public;
			ge_add(&sum,&ge_public,&ge_eightpoint);
			ge_p1p1_to_p3(&ge_public,&sum);
		}
#ifdef STATISTICS
		t1 = now();
#endif
		ge_p3_batchtobytes_destructive_1(bufs->pk_batch,bufs->ge_batch,bufs->tmp_batch,BATCHNUM);
#ifdef STATISTICS
		t2 = now();
#endif
		// 批量base32编码
		// SIMD plug-in point: batch base32 encoding
#ifdef __AVX2__
    avx2_base32_encode_bulk((char *)base32buf, (const uint8_t *)bufs->pk_batch, BATCHNUM, PUBONION_LEN, ONION_ADDRLEN);
#else
    base32_to_bulk((char *)base32buf, (const u8 *)bufs->pk_batch, BATCHNUM, PUBONION_LEN, ONION_ADDRLEN);
#endif
#ifdef STATISTICS
		t3 = now();
#endif
		// 批量筛选优化
		for (size_t b = 0; b < BATCHNUM; ++b) {
			bufs->onion_ptrs[b] = bufs->sname[b];
		}
#if defined(ENABLE_REGEX)
		filters_match_regex_bulk(bufs->onion_ptrs, bufs->filter_results, BATCHNUM);
#elif defined(ENABLE_GLOB)
		// SIMD plug-in point: batch filtering
#ifdef __AVX2__
    avx2_filters_match_glob_bulk(bufs->onion_ptrs, bufs->filter_results, BATCHNUM);
#else
    filters_match_glob_bulk(bufs->onion_ptrs, bufs->filter_results, BATCHNUM);
#endif
#else
		filters_match_bin_bulk(bufs->onion_ptrs, bufs->filter_results, BATCHNUM);
#endif
#ifdef STATISTICS
		t4 = now();
#endif
		// --- 批量公钥校验和哈希 ---
		for (size_t b = 0; b < BATCHNUM; ++b) {
			memcpy(bufs->hashsrc_b[b], checksumstr, checksumstrlen);
			memcpy(bufs->hashsrc_b[b] + checksumstrlen, bufs->pk_batch[b], PUBLIC_LEN);
			bufs->hashsrc_bulk[b] = bufs->hashsrc_b[b];
			bufs->hashsrc_len_bulk[b] = checksumstrlen + PUBLIC_LEN;
			bufs->pk_bulk[b] = &bufs->pk_batch[b][PUBLIC_LEN];
			bufs->pk_outlen_bulk[b] = 32;
		}
		// SIMD plug-in point: batch hashing
#ifdef __AVX2__
    avx2_keccak_bulk(136, (const u8 **)bufs->hashsrc_bulk, bufs->hashsrc_len_bulk, 0x1f, bufs->pk_bulk, bufs->pk_outlen_bulk, BATCHNUM);
#else
    Keccak_bulk(136, (const u8 **)bufs->hashsrc_bulk, bufs->hashsrc_len_bulk, 0x1f, bufs->pk_bulk, bufs->pk_outlen_bulk, BATCHNUM);
#endif
#ifdef STATISTICS
		double t5 = now();
		t_keygen += t1-t0;
		t_base32 += t2-t1;
		t_filter += t4-t3;
		t_hash += t5-t4;
		t_other += (t0-t5);
		n_samples++;
#endif
	}
	goto initseed;

end:

	POSTFILTER

	sodium_memzero(secret,sizeof(secret));
	sodium_memzero(seed,sizeof(seed));

	if (need_free) free_batch_buffers(bufs);
	return 0;
}
