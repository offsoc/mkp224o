
// PERFORMANCE NOTES
// - All batch buffers are 32-byte aligned for AVX2 SIMD (future-proof for AVX512).
// - Batch main loop is designed for vectorization (see SIMD ENTRY POINT comments).
// - Per-thread stats should be padded to avoid false sharing (see struct statstruct).
// - For NUMA/affinity, see TODO comments in worker launch (main.c).
// - Memory layout is contiguous for cache efficiency.

#ifdef PASSPHRASE
// Structure holding all batch buffers for high-throughput deterministic keygen/encoding/filtering
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

// High-performance deterministic batch worker: generates, encodes, filters, and hashes keys in bulk
// If task is a batch_buffers pointer, uses external buffers (main process); otherwise allocates internally (sampling)
void *CRYPTO_NAMESPACE(worker_batch_pass)(void *task)
{
	union pubonionunion pubonion;
	u8 * const pk = &pubonion.raw[PKPREFIX_SIZE];
	u8 secret[SKPREFIX_SIZE + SECRET_LEN];
	u8 * const sk = &secret[SKPREFIX_SIZE];
	u8 seed[SEED_LEN];
	u8 hashsrc[checksumstrlen + PUBLIC_LEN + 1];
	u8 wpk[PUBLIC_LEN + 1];
	ge_p3 ALIGN(16) ge_public;
	char *sname;

	// state to keep batch data
	size_t batchnum = BATCHNUM;
	struct batch_buffers *bufs = NULL;
	int need_free = 0;
	if (task && ((uintptr_t)task % sizeof(void *) == 0)) {
		bufs = (struct batch_buffers *)task;
	} else {
		bufs = alloc_batch_buffers(batchnum);
		need_free = 1;
		if (!bufs) return NULL;
	}

	size_t counter,oldcounter;
	size_t i;

#ifdef STATISTICS
	struct statstruct *st = (struct statstruct *)task;
	double t_keygen = 0, t_base32 = 0, t_filter = 0, t_hash = 0, t_other = 0;
	int n_samples = 0;
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
	// char sname[BATCHNUM][64]; // This line is removed as sname is now a pointer

	int seednear;

initseed:

#ifdef STATISTICS
	++st->numrestart.v;
#endif

	seednear = 0;

	pthread_mutex_lock(&determseed_mutex);
	for (int i = 0; i < SEED_LEN; i++)
		if (++determseed[i])
			break;
	memcpy(seed,determseed,SEED_LEN);
	pthread_mutex_unlock(&determseed_mutex);

	ed25519_seckey_expand(sk,seed);

	ge_scalarmult_base(&ge_public,sk);

	// SIMD ENTRY POINT: The following main loop is designed for AVX2/AVX512 vectorization.
	for (counter = oldcounter = 0;counter < DETERMINISTIC_LOOP_COUNT - (BATCHNUM - 1) * 8;counter += BATCHNUM * 8) {
		ge_p1p1 ALIGN(16) sum;

		if (unlikely(endwork))
			goto end;

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
		// Batch base32 encoding (SIMD plug-in point)
#ifdef __AVX2__
        avx2_base32_encode_bulk((char*)base32buf, (const uint8_t*)bufs->pk_batch, BATCHNUM, PUBONION_LEN, ONION_ADDRLEN);
#else
        base32_to_bulk((char*)base32buf, (const u8*)bufs->pk_batch, BATCHNUM, PUBONION_LEN, ONION_ADDRLEN);
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
		filters_match_glob_bulk(bufs->onion_ptrs, bufs->filter_results, BATCHNUM);
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
		FIPS202_SHA3_256_bulk((const u8 **)bufs->hashsrc_bulk, bufs->hashsrc_len_bulk, bufs->pk_bulk, bufs->pk_outlen_bulk, BATCHNUM);
#ifdef STATISTICS
		double t5 = now();
		t_keygen += t1-t0;
		t_base32 += t2-t1;
		t_filter += t4-t3;
		t_hash += t5-t4;
		t_other += (t0-t5);
		n_samples++;
#endif

#ifdef STATISTICS
		st->numcalc.v += BATCHNUM;
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
					addsztoscalar32(sk,counter + (b * 8) - oldcounter);
					oldcounter = counter + (b * 8);
					if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
						goto initseed;
					reseedright(sk);
					ADDNUMSUCCESS;
					memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
					FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
					pk[PUBLIC_LEN + 2] = 0x03;
					snprintf(bufs->sname[b], 64, "%s.onion", base32buf[b]);
					onionready(bufs->sname[b],secret,pubonion.raw,seednear && pw_warnnear);
					pk[PUBLIC_LEN] = 0;
					if (pw_skipnear)
						goto initseed;
					seednear = 1;
#endif
				} else if (filter_mode == 2) {
					if (!filters_match_glob(base32buf[b]))
						continue;
					// found!
					ge_p3_batchtobytes_destructive_finish(bufs->pk_batch[b],&bufs->ge_batch[b]);
					memcpy(pk,bufs->pk_batch[b],PUBLIC_LEN);
					addsztoscalar32(sk,counter + (b * 8) - oldcounter);
					oldcounter = counter + (b * 8);
					if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
						goto initseed;
					reseedright(sk);
					ADDNUMSUCCESS;
					memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
					FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
					pk[PUBLIC_LEN + 2] = 0x03;
					snprintf(bufs->sname[b], 64, "%s.onion", base32buf[b]);
					onionready(bufs->sname[b],secret,pubonion.raw,seednear && pw_warnnear);
					pk[PUBLIC_LEN] = 0;
					if (pw_skipnear)
						goto initseed;
					seednear = 1;
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
						addsztoscalar32(sk,counter + (b * 8) - oldcounter);
						oldcounter = counter + (b * 8);
						// sanity check
						if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
							goto initseed;

						// reseed right half of key to avoid reuse, it won't change public key anyway
						reseedright(sk);

						ADDNUMSUCCESS;

						// calc checksum
						memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
						FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
						// version byte
						pk[PUBLIC_LEN + 2] = 0x03;
						// full name
						snprintf(bufs->sname[b], 64, "%s.onion", base32buf[b]);
						onionready(bufs->sname[b],secret,pubonion.raw,seednear && pw_warnnear);
						pk[PUBLIC_LEN] = 0; // what is this for?

						if (pw_skipnear)
							goto initseed;
						seednear = 1;
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
		FIPS202_SHA3_256_bulk((const u8 **)bufs->hashsrc_bulk, bufs->hashsrc_len_bulk, bufs->pk_bulk, bufs->pk_outlen_bulk, BATCHNUM);
		// --- 批量哈希结束 ---
	}
	// continue if have leftovers, DETERMINISTIC_LOOP_COUNT - counter < BATCHNUM * 8
	// can't have leftovers in theory if BATCHNUM was power of 2 and smaller than DETERMINISTIC_LOOP_COUNT bound
#if (BATCHNUM & (BATCHNUM - 1)) || (BATCHNUM * 8) > DETERMINISTIC_LOOP_COUNT
	if (counter < DETERMINISTIC_LOOP_COUNT) {
		ge_p1p1 ALIGN(16) sum;

		if (unlikely(endwork))
			goto end;

		const size_t remaining = (DETERMINISTIC_LOOP_COUNT - counter) / 8;

		for (size_t b = 0;b < remaining;++b) {
			bufs->ge_batch[b] = ge_public;
			ge_add(&sum,&ge_public,&ge_eightpoint);
			ge_p1p1_to_p3(&ge_public,&sum);
		}
		// NOTE: leaves unfinished one bit at the very end
		ge_p3_batchtobytes_destructive_1(bufs->pk_batch,bufs->ge_batch,bufs->tmp_batch,remaining);

#ifdef STATISTICS
		st->numcalc.v += remaining;
#endif

		for (size_t b = 0;b < remaining;++b) {
			if (filter_mode == 1) {
#ifdef PCRE2FILTER
				if (!filters_match_regex(base32buf[b]))
					continue;
				// found!
				ge_p3_batchtobytes_destructive_finish(bufs->pk_batch[b],&bufs->ge_batch[b]);
				memcpy(pk,bufs->pk_batch[b],PUBLIC_LEN);
				addsztoscalar32(sk,counter + (b * 8) - oldcounter);
				oldcounter = counter + (b * 8);
				if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
					goto initseed;
				reseedright(sk);
				ADDNUMSUCCESS;
				memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
				FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
				pk[PUBLIC_LEN + 2] = 0x03;
				snprintf(bufs->sname[b], 64, "%s.onion", base32buf[b]);
				onionready(bufs->sname[b],secret,pubonion.raw,seednear && pw_warnnear);
				pk[PUBLIC_LEN] = 0;
				if (pw_skipnear)
					goto initseed;
				seednear = 1;
#endif
			} else if (filter_mode == 2) {
				if (!filters_match_glob(base32buf[b]))
					continue;
				// found!
				ge_p3_batchtobytes_destructive_finish(bufs->pk_batch[b],&bufs->ge_batch[b]);
				memcpy(pk,bufs->pk_batch[b],PUBLIC_LEN);
				addsztoscalar32(sk,counter + (b * 8) - oldcounter);
				oldcounter = counter + (b * 8);
				if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
					goto initseed;
				reseedright(sk);
				ADDNUMSUCCESS;
				memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
				FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
				pk[PUBLIC_LEN + 2] = 0x03;
				snprintf(bufs->sname[b], 64, "%s.onion", base32buf[b]);
				onionready(bufs->sname[b],secret,pubonion.raw,seednear && pw_warnnear);
				pk[PUBLIC_LEN] = 0;
				if (pw_skipnear)
					goto initseed;
				seednear = 1;
			} else {
				DOFILTER(i,bufs->pk_batch[b],{
					if (numwords > 1) {
						shiftpk(wpk,bufs->pk_batch[b],filter_len(i));
						size_t j;
						for (int w = 1;;) {
							DOFILTER(j,wpk,goto secondfind2);
							goto next2;
						secondfind2:
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
					addsztoscalar32(sk,counter + (b * 8) - oldcounter);
					oldcounter = counter + (b * 8);
					// sanity check
					if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
						goto initseed;

					// reseed right half of key to avoid reuse, it won't change public key anyway
					reseedright(sk);

					ADDNUMSUCCESS;

					// calc checksum
					memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
					FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
					// version byte
					pk[PUBLIC_LEN + 2] = 0x03;
					// full name
					snprintf(bufs->sname[b], 64, "%s.onion", base32buf[b]);
					onionready(bufs->sname[b],secret,pubonion.raw,seednear && pw_warnnear);
					pk[PUBLIC_LEN] = 0; // what is this for?

					if (pw_skipnear)
						goto initseed;
					seednear = 1;
				});
			}
		next2:
			;
		}
	}
#endif // (BATCHNUM & (BATCHNUM - 1)) || (BATCHNUM * 8) > DETERMINISTIC_LOOP_COUNT
	goto initseed;

end:

	POSTFILTER

	sodium_memzero(secret,sizeof(secret));
	sodium_memzero(seed,sizeof(seed));
	if (need_free) free_batch_buffers(bufs);
	return 0;
}
#endif // PASSPHRASE
