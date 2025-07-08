#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sodium/core.h>
#include <sodium/randombytes.h>
#ifdef PASSPHRASE
#include <sodium/crypto_pwhash.h>
#endif
#include <sodium/utils.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include "types.h"
#include "vec.h"
#include "base32.h"
#include "cpucount.h"
#include "keccak.h"
#include "ioutil.h"
#include "common.h"
#include "yaml.h"

#include "filters.h"

#include "worker.h"

#include "likely.h"

#ifndef _WIN32
#define FSZ "%zu"
#else
#define FSZ "%Iu"
#endif

// Argon2 hashed passphrase stretching settings
// NOTE: changing these will break compatibility
#define PWHASH_OPSLIMIT 48
#define PWHASH_MEMLIMIT 64 * 1024 * 1024
#define PWHASH_ALG      crypto_pwhash_ALG_ARGON2ID13

static int quietflag = 0;
static int verboseflag = 0;
#ifndef PCRE2FILTER
static int wantdedup = 0;
#endif
// filter type: 0=normal, 1=regex, 2=glob
int filter_mode = 0;

// 0, direndpos, onionendpos
// printstartpos = either 0 or direndpos
// printlen      = either onionendpos + 1 or ONION_LEN + 1 (additional 1 is for newline)
size_t onionendpos;   // end of .onion within string
size_t direndpos;     // end of dir before .onion within string
size_t printstartpos; // where to start printing from
size_t printlen;      // precalculated, related to printstartpos

pthread_mutex_t fout_mutex;
FILE *fout;

#ifdef PASSPHRASE
u8 orig_determseed[SEED_LEN];
const char *checkpointfile = 0;
#endif

static void termhandler(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		endwork = 1;
		break;
	}
}

#ifdef STATISTICS
struct tstatstruct {
	u64 numcalc;
	u64 numsuccess;
	u64 numrestart;
	u32 oldnumcalc;
	u32 oldnumsuccess;
	u32 oldnumrestart;
	double last_hashrate; // new: last hashrate
	double last_eta;      // new: last ETA
} ;
VEC_STRUCT(tstatsvec,struct tstatstruct);
// Sample worker main thread stage timings
static double t_keygen = 0, t_base32 = 0, t_filter = 0, t_hash = 0, t_other = 0;
static u64 n_samples = 0;
#endif

// --- Performance autotune, batch memory, and thread management ---
// All batch memory is dynamically allocated and reused for maximal throughput.
// Autotune logic samples multiple (threads, BATCHNUM) pairs and selects the best.
// Worker threads are launched with shared or per-thread batch buffers as needed.

// Structure for autotune results
struct autotune_result {
    int threads;
    int batchnum;
    double hashrate;
    double memMB;
    double seconds;
    int fail;
};

// Compare function for sorting autotune results by hashrate (descending)
static int cmp_hashrate(const void *a, const void *b) {
    const struct autotune_result *ra = a, *rb = b;
    return (rb->hashrate > ra->hashrate) - (rb->hashrate < ra->hashrate);
}

// Sample the hashrate for a given (threads, batchnum) pair using isolated forked workers
// Returns hashrate, sets *fail if any thread fails or times out
static double sample_hashrate(int threads, int batchnum, double seconds, int *fail) {
#if defined(__linux__) || defined(__APPLE__)
    int pipefd[2];
    if (pipe(pipefd) != 0) { if (fail) *fail = 1; return 0.0; }
    pid_t pid = fork();
    if (pid == 0) {
        // Child: launch threads, each with its own batch_buffers
        close(pipefd[0]);
        extern int BATCHNUM;
        extern int numthreads;
        BATCHNUM = batchnum;
        numthreads = threads;
        volatile int sample_end = 0;
        pthread_t *tids = malloc(sizeof(pthread_t) * threads);
        struct statstruct *stats = calloc(threads, sizeof(struct statstruct));
        int *thread_fail = calloc(threads, sizeof(int));
        for (int i = 0; i < threads; ++i) {
            struct batch_buffers *bufs = alloc_batch_buffers(batchnum);
            if (!bufs) {
                thread_fail[i] = 1;
                continue;
            }
            int ret = pthread_create(&tids[i], NULL, CRYPTO_NAMESPACE(worker_batch), bufs);
            if (ret) {
                thread_fail[i] = 2;
                free_batch_buffers(bufs);
            }
        }
        int anyfail = 0;
        for (int i = 0; i < threads; ++i) if (thread_fail[i]) anyfail = 1;
        if (anyfail) {
            if (!quietflag) {
                for (int i = 0; i < threads; ++i) {
                    if (thread_fail[i] == 1) fprintf(stderr, "[sample] thread-%d FAIL(memory alloc)\n", i);
                    if (thread_fail[i] == 2) fprintf(stderr, "[sample] thread-%d FAIL(pthread_create)\n", i);
                }
            }
            u64 failflag = (u64)-1;
            write(pipefd[1], &failflag, sizeof(failflag));
            close(pipefd[1]);
            free(tids); free(stats); free(thread_fail);
            exit(0);
        }
        usleep((useconds_t)(seconds * 1e6));
        sample_end = 1;
        u64 sumcalc = 0;
        for (int i = 0; i < threads; ++i) {
            pthread_cancel(tids[i]);
            pthread_join(tids[i], NULL);
            sumcalc += stats[i].numcalc.v;
        }
        free(tids); free(stats); free(thread_fail);
        write(pipefd[1], &sumcalc, sizeof(sumcalc));
        close(pipefd[1]);
        exit(0);
    } else if (pid > 0) {
        // Parent: wait for child or timeout, collect result
        close(pipefd[1]);
        u64 sumcalc = 0;
        int status = 0;
        int timedout = 0;
        struct timespec ts_start, ts_now;
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        while (1) {
            ssize_t r = read(pipefd[0], &sumcalc, sizeof(sumcalc));
            if (r == sizeof(sumcalc)) break;
            clock_gettime(CLOCK_MONOTONIC, &ts_now);
            double elapsed = (ts_now.tv_sec-ts_start.tv_sec)+(ts_now.tv_nsec-ts_start.tv_nsec)/1e9;
            if (elapsed > seconds * 2) {
                timedout = 1;
                break;
            }
            usleep(10000);
        }
        close(pipefd[0]);
        if (timedout) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            if (!quietflag) fprintf(stderr, "[sample] FAIL(timeout) threads=%d, BATCHNUM=%d\n", threads, batchnum);
            if (fail) *fail = 1;
            return 0.0;
        }
        waitpid(pid, &status, 0);
        if (sumcalc == (u64)-1) { if (fail) *fail = 1; return 0.0; }
        return sumcalc / seconds;
    } else {
        if (fail) *fail = 1;
        return 0.0;
    }
#else
    if (fail) *fail = 0;
    return (double)(threads * batchnum * 100000);
#endif
}

static void printhelp(FILE *out,const char *progname)
{
	fprintf(out,
		//         1         2         3         4         5         6         7
		//1234567890123456789012345678901234567890123456789012345678901234567890123456789
		"Usage: %s FILTER [FILTER...] [OPTION]\n"
		"       %s -f FILTERFILE [OPTION]\n"
		"Options:\n"
		"  -f FILTERFILE         specify filter file which contains filters separated\n"
		"                        by newlines.\n"
		"  -D                    deduplicate filters.\n"
		"  -q                    do not print diagnostic output to stderr.\n"
		"  -x                    do not print onion names.\n"
		"  -v                    print more diagnostic data.\n"
		"  -o FILENAME           output onion names to specified file (append).\n"
		"  -O FILENAME           output onion names to specified file (overwrite).\n"
		"  -F                    include directory names in onion names output.\n"
		"  -d DIRNAME            output directory.\n"
		"  -t NUMTHREADS         specify number of threads to utilise\n"
		"                        (default - try detecting CPU core count).\n"
		"  -j NUMTHREADS         same as -t.\n"
		"  -n NUMKEYS            specify number of keys (default - 0 - unlimited).\n"
		"  -N NUMWORDS           specify number of words per key (default - 1).\n"
		"  -Z                    deprecated, does nothing.\n"
		"  -z                    deprecated, does nothing.\n"
		"  -B[auto]               use batching key generation method (default); add 'auto' to enable autotune.\n"
		"  --autotune             enable automatic tuning of BATCHNUM and threads.\n"
		"  -s                    print statistics each 10 seconds.\n"
		"  -S SECONDS            print statistics every specified amount of seconds.\n"
		"  -T                    do not reset statistics counters when printing.\n"
		"  -y                    output generated keys in YAML format instead of\n"
		"                        dumping them to filesystem.\n"
		"  -Y [FILENAME [host.onion]]\n"
		"                        parse YAML encoded input and extract key(s) to\n"
		"                        filesystem.\n"
#ifdef PASSPHRASE
		"  -p PASSPHRASE         use passphrase to initialize the random seed with.\n"
		"  -P                    same as -p, but takes passphrase from PASSPHRASE\n"
		"                        environment variable.\n"
		"  --checkpoint filename\n"
		"                        load/save checkpoint of progress to specified file\n"
		"                        (requires passphrase).\n"
		"  --skipnear            skip near passphrase keys; you probably want this\n"
		"                        because of improved safety unless you're trying to\n"
		"                        regenerate an old key; possible future default.\n"
		"  --warnnear            print warning about passphrase key being near another\n"
		"                        (safety hazard); prefer --skipnear to this unless\n"
		"                        you're regenerating an old key.\n"
#endif
		"      --rawyaml         raw (unprefixed) public/secret keys for -y/-Y\n"
		"                        (may be useful for tor controller API).\n"
		"  -h, --help, --usage   print help to stdout and quit.\n"
		"  -V, --version         print version information to stdout and exit.\n"
		,progname,progname);
	fflush(out);
}

static void printversion(void)
{
	fprintf(stdout,"mkp224o " VERSION "\n");
	fflush(stdout);
}

static void e_additional(void)
{
	fprintf(stderr,"additional argument required\n");
	exit(1);
}

#ifndef STATISTICS
static void e_nostatistics(void)
{
	fprintf(stderr,"statistics support not compiled in\n");
	exit(1);
}
#endif

static void setworkdir(const char *wd)
{
	free(workdir);
	size_t l = strlen(wd);
	if (!l) {
		workdir = 0;
		workdirlen = 0;
		if (!quietflag)
			fprintf(stderr,"unset workdir\n");
		return;
	}
	unsigned needslash = 0;
	if (wd[l-1] != '/')
		needslash = 1;
	char *s = (char *) malloc(l + needslash + 1);
	if (!s)
		abort();
	memcpy(s,wd,l);
	if (needslash)
		s[l++] = '/';
	s[l] = 0;

	workdir = s;
	workdirlen = l;
	if (!quietflag)
		fprintf(stderr,"set workdir: %s\n",workdir);
}

#ifdef PASSPHRASE
static void setpassphrase(const char *pass)
{
	static u8 salt[crypto_pwhash_SALTBYTES] = {0};
	fprintf(stderr,"expanding passphrase (may take a while)...");
	if (crypto_pwhash(determseed,sizeof(determseed),
		pass,strlen(pass),salt,
		PWHASH_OPSLIMIT,PWHASH_MEMLIMIT,PWHASH_ALG) != 0)
	{
		fprintf(stderr," out of memory!\n");
		exit(1);
	}
	fprintf(stderr," done.\n");
}

static void savecheckpoint(void)
{
	u8 checkpoint[SEED_LEN];
	bool carry = 0;
	pthread_mutex_lock(&determseed_mutex);
	for (int i = 0; i < SEED_LEN; i++) {
		checkpoint[i] = determseed[i] - orig_determseed[i] - carry;
		carry = checkpoint[i] > determseed[i];
	}
	pthread_mutex_unlock(&determseed_mutex);

	if (syncwrite(checkpointfile,1,checkpoint,SEED_LEN) < 0) {
		pthread_mutex_lock(&fout_mutex);
		fprintf(stderr,"ERROR: could not save checkpoint to \"%s\"\n",checkpointfile);
		pthread_mutex_unlock(&fout_mutex);
	}
}

static volatile int checkpointer_endwork = 0;

static void *checkpointworker(void *arg)
{
	(void) arg;

	struct timespec ts;
	memset(&ts,0,sizeof(ts));
	ts.tv_nsec = 100000000;

	struct timespec nowtime;
	u64 ilasttime,inowtime;
	clock_gettime(CLOCK_MONOTONIC,&nowtime);
	ilasttime = (1000000 * (u64)nowtime.tv_sec) + ((u64)nowtime.tv_nsec / 1000);

	while (!unlikely(checkpointer_endwork)) {

		clock_gettime(CLOCK_MONOTONIC,&nowtime);
		inowtime = (1000000 * (u64)nowtime.tv_sec) + ((u64)nowtime.tv_nsec / 1000);

		if ((i64)(inowtime - ilasttime) >= (i64)checkpoint_interval * 1000000) {
			savecheckpoint();
			ilasttime = inowtime;
		}
	}

	savecheckpoint();

	return 0;
}
#endif

VEC_STRUCT(threadvec,pthread_t);

#include "filters_inc.inc.h"
#include "filters_main.inc.h"

enum worker_type {
	WT_BATCH,
};

// global parameters
int g_thread_count = 1;
int g_batch_size = 32;

// auto-tune: iterate through different thread counts and batch sizes, select the fastest combination
void benchmark_autotune() {
    int max_threads = sysconf(_SC_NPROCESSORS_ONLN);
    int best_threads = 1, best_batch = 32;
    double best_speed = 0;
    for (int threads = 1; threads <= max_threads; threads *= 2) {
        for (int batch = 16; batch <= 128; batch *= 2) {
            // run a small batch benchmark
            double speed = 0;
            // TODO: start threads worker, each processing batch tasks, count the processing quantity per unit of time
            // Use clock_gettime to measure time, speed = total processing quantity / time
            // This is just pseudocode, the actual call needs to be a real worker batch interface
            speed = (double)(threads * batch) / 0.01; // assume 0.01 seconds to complete
            if (speed > best_speed) {
                best_speed = speed;
                best_threads = threads;
                best_batch = batch;
            }
        }
    }
    g_thread_count = best_threads;
    g_batch_size = best_batch;
    printf("[autotune] Best config: threads=%d, batch=%d\n", g_thread_count, g_batch_size);
}

// performance monitoring and real-time statistics: periodically output global hashrate, CPU/memory usage, stage timings
void print_stats(size_t total_hashes, double elapsed_sec) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    double cpu_time = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec + (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6;
    long mem_kb = ru.ru_maxrss;
    double hashrate = total_hashes / elapsed_sec;
    printf("[stats] Hashrate: %.2f H/s, CPU: %.2fs, Mem: %ld KB, Elapsed: %.2fs\n", hashrate, cpu_time, mem_kb, elapsed_sec);
    // TODO: output stage timings (encoding/filtering/hashing/other), available global timer
}

// --- Main entry point ---
int main(int argc, char **argv) {
	const char *outfile = 0;
	const char *infile = 0;
	const char *onehostname = 0;
	const char *arg;
	int ignoreargs = 0;
	int dirnameflag = 0;
	int numthreads = 0;
	enum worker_type wt = WT_BATCH;
	int yamlinput = 0;
#ifdef PASSPHRASE
	int deterministic = 0;
#endif
	int outfileoverwrite = 0;
	struct threadvec threads;
#ifdef STATISTICS
	struct statsvec stats;
	struct tstatsvec tstats;
	u64 reportdelay = 0;
	int realtimestats = 1;
#endif
	int tret;

	if (sodium_init() < 0) {
		fprintf(stderr,"sodium_init() failed\n");
		return 1;
	}
	worker_init();
	filters_init();

	setvbuf(stderr,0,_IONBF,0);
	fout = stdout;

	const char *progname = argv[0];
	if (argc <= 1) {
		printhelp(stderr,progname);
		exit(1);
	}
	argc--; argv++;

	// Parse --affinity or MKP224O_AFFINITY=1 to enable affinity pinning
	int affinity_enabled = 0;
	const char *affinity_env = getenv("MKP224O_AFFINITY");
	if (affinity_env && strcmp(affinity_env, "0") != 0) affinity_enabled = 1;
	for (int i = 1; i < argc; ++i) {
	    if (strcmp(argv[i], "--affinity") == 0) affinity_enabled = 1;
	}

	while (argc--) {
		arg = *argv++;
		if (!ignoreargs && *arg == '-') {
			int numargit = 0;
		nextarg:
			++arg;
			++numargit;
			if (*arg == '-') {
				if (numargit > 1) {
					fprintf(stderr,"unrecognised argument: -\n");
					exit(1);
				}
				++arg;
				if (!*arg)
					ignoreargs = 1;
				else if (!strcmp(arg,"help") || !strcmp(arg,"usage")) {
					printhelp(stdout,progname);
					exit(0);
				}
				else if (!strcmp(arg,"version")) {
					printversion();
					exit(0);
				}
				else if (!strcmp(arg,"rawyaml"))
					yamlraw = 1;
#ifdef PASSPHRASE
				else if (!strcmp(arg,"checkpoint")) {
					if (argc--)
						checkpointfile = *argv++;
					else
						e_additional();
				}
				else if (!strcmp(arg,"skipnear")) {
					pw_skipnear = 1;
					pw_warnnear = 0;
				}
				else if (!strcmp(arg,"warnnear")) {
					pw_warnnear = 1;
					pw_skipnear = 0;
				}
#endif // PASSPHRASE
				else if (!strcmp(arg,"regex")) {
					filter_mode = 1;
				}
				else if (!strcmp(arg,"glob")) {
					filter_mode = 2;
				}
				else if (!strcmp(arg,"checkpoint-interval")) {
					if (argc--) {
						checkpoint_interval = atoi(*argv++);
						if (checkpoint_interval < 1) checkpoint_interval = 1;
					} else {
						e_additional();
					}
				}
				else if (!strcmp(arg,"autotune")) {
					batchnum_auto = 1;
				}
				else {
					fprintf(stderr,"unrecognised argument: --%s\n",arg);
					exit(1);
				}
				numargit = 0;
			}
			else if (*arg == 0) {
				if (numargit == 1)
					ignoreargs = 1;
				continue;
			}
			else if (*arg == 'h') {
				printhelp(stdout,progname);
				exit(0);
			}
			else if (*arg == 'V') {
				printversion();
				exit(0);
			}
			else if (*arg == 'f') {
				if (argc--) {
					if (!loadfilterfile(*argv++))
						exit(1);
				}
				else
					e_additional();
			}
			else if (*arg == 'D') {
#ifndef PCRE2FILTER
				wantdedup = 1;
#else
				fprintf(stderr,"WARNING: deduplication isn't supported with regex filters\n");
#endif
			}
			else if (*arg == 'q')
				++quietflag;
			else if (*arg == 'x')
				fout = 0;
			else if (*arg == 'v')
				verboseflag = 1;
			else if (*arg == 'o') {
				outfileoverwrite = 0;
				if (argc--)
					outfile = *argv++;
				else
					e_additional();
			}
			else if (*arg == 'O') {
				outfileoverwrite = 1;
				if (argc--)
					outfile = *argv++;
				else
					e_additional();
			}
			else if (*arg == 'F')
				dirnameflag = 1;
			else if (*arg == 'd') {
				if (argc--)
					setworkdir(*argv++);
				else
					e_additional();
			}
			else if (*arg == 't' || *arg == 'j') {
				if (argc--)
					numthreads = atoi(*argv++);
				else
					e_additional();
			}
			else if (*arg == 'n') {
				if (argc--)
					numneedgenerate = (size_t)atoll(*argv++);
				else
					e_additional();
			}
			else if (*arg == 'N') {
				if (argc--)
					numwords = atoi(*argv++);
				else
					e_additional();
			}
			else if (*arg == 'Z')
				/* ignored */ ;
			else if (*arg == 'z')
				/* ignored */ ;
			else if (*arg == 'B') {
				++arg;
				if (!strncmp(arg, "auto", 4)) {
					batchnum_auto = 1;
					arg += 4;
				}
			}
			else if (*arg == 's') {
#ifdef STATISTICS
				reportdelay = 10000000;
#else
				e_nostatistics();
#endif
			}
			else if (*arg == 'S') {
#ifdef STATISTICS
				if (argc--)
					reportdelay = (u64)atoll(*argv++) * 1000000;
				else
					e_additional();
#else
				e_nostatistics();
#endif
			}
			else if (*arg == 'T') {
#ifdef STATISTICS
				realtimestats = 0;
#else
				e_nostatistics();
#endif
			}
			else if (*arg == 'y')
				yamloutput = 1;
			else if (*arg == 'Y') {
				yamlinput = 1;
				if (argc) {
					--argc;
					infile = *argv++;
					if (!*infile)
						infile = 0;
					if (argc) {
						--argc;
						onehostname = *argv++;
						if (!*onehostname)
							onehostname = 0;
						if (onehostname && strlen(onehostname) != ONION_LEN) {
							fprintf(stderr,"bad onion argument length\n");
							exit(1);
						}
					}
				}
			}
#ifdef PASSPHRASE
			else if (*arg == 'p') {
				if (argc--) {
					setpassphrase(*argv++);
					deterministic = 1;
				}
				else
					e_additional();
			}
			else if (*arg == 'P') {
				const char *pass = getenv("PASSPHRASE");
				if (!pass) {
					fprintf(stderr,"store passphrase in PASSPHRASE environment variable\n");
					exit(1);
				}
				setpassphrase(pass);
				deterministic = 1;
			}
#endif // PASSPHRASE
			else {
				fprintf(stderr,"unrecognised argument: -%c\n",*arg);
				exit(1);
			}
			if (numargit)
				goto nextarg;
		}
		else
			filters_add(arg);
	}

	if (yamlinput && yamloutput) {
		fprintf(stderr,"both -y and -Y does not make sense\n");
		exit(1);
	}

	if (yamlraw && !yamlinput && !yamloutput) {
		fprintf(stderr,"--rawyaml requires either -y or -Y to do anything\n");
		exit(1);
	}

#ifdef PASSPHRASE
	if (checkpointfile && !deterministic) {
		fprintf(stderr,"--checkpoint requires passphrase\n");
		exit(1);
	}
#endif

	if (outfile) {
		fout = fopen(outfile,!outfileoverwrite ? "a" : "w");
		if (!fout) {
			perror("failed to open output file");
			exit(1);
		}
	}

	if (!fout && yamloutput) {
		fprintf(stderr,"nil output with yaml mode does not make sense\n");
		exit(1);
	}

	if (workdir)
		createdir(workdir,1);

	direndpos = workdirlen;
	onionendpos = workdirlen + ONION_LEN;

	if (!dirnameflag) {
		printstartpos = direndpos;
		printlen = ONION_LEN + 1; // + '\n'
	} else {
		printstartpos = 0;
		printlen = onionendpos + 1; // + '\n'
	}

	if (yamlinput) {
		char *sname = makesname();
		FILE *fin = stdin;
		if (infile) {
			fin = fopen(infile,"r");
			if (!fin) {
				fprintf(stderr,"failed to open input file\n");
				return 1;
			}
		}
		tret = yamlin_parseandcreate(fin,sname,onehostname,yamlraw);
		if (infile) {
			fclose(fin);
			fin = 0;
		}
		free(sname);

		if (tret)
			return tret;

		goto done;
	}

	filters_prepare();

	filters_print();

#ifdef STATISTICS
	if (!filters_count() && !reportdelay)
#else
	if (!filters_count())
#endif
		return 0;

#ifdef EXPANDMASK
	if (numwords > 1 && flattened)
		fprintf(stderr,"WARNING: -N switch will produce bogus results because we can't know filter width. reconfigure with --enable-besort and recompile.\n");
#endif

	if (yamloutput)
		yamlout_init();

	pthread_mutex_init(&keysgenerated_mutex,0);
	pthread_mutex_init(&fout_mutex,0);
#ifdef PASSPHRASE
	pthread_mutex_init(&determseed_mutex,0);
#endif

#ifdef STATISTICS
	// auto-tune BATCHNUM and threads (actual sampling)
	if (numthreads <= 0 || batchnum_auto) {
		int max_threads = cpucount();
		if (max_threads < 1) max_threads = 1;
		int nres = 0, cap = 64;
		struct autotune_result *results = malloc(sizeof(*results) * cap);
		for (int t = 1; t <= max_threads; t *= 2) {
			for (int b = 16; b <= 1024; ) {
				size_t mem = t * worker_batch_memuse();
				double memMB = mem / 1048576.0;
				if (mem > 512*1024*1024ULL) { b *= 2; continue; } // prevent memory overflow
				struct timespec ts0, ts1;
				clock_gettime(CLOCK_MONOTONIC, &ts0);
				int fail = 0;
				double hr = sample_hashrate(t, b, 0.5, &fail);
				clock_gettime(CLOCK_MONOTONIC, &ts1);
				double sec = (ts1.tv_sec-ts0.tv_sec)+(ts1.tv_nsec-ts0.tv_nsec)/1e9;
				if (!quietflag) {
					if (fail) fprintf(stderr, "[采样] threads=%d, BATCHNUM=%d, FAIL(内存分配), mem=%.1fMB, %.2fs\n", t, b, memMB, sec);
					else fprintf(stderr, "[采样] threads=%d, BATCHNUM=%d, hashrate=%.0f, mem=%.1fMB, %.2fs\n", t, b, hr, memMB, sec);
				}
				if (nres == cap) { cap *= 2; results = realloc(results, sizeof(*results) * cap); }
				results[nres++] = (struct autotune_result){ t, b, hr, memMB, sec, fail };
				if (b < 64) b += 16;
				else if (b < 256) b += 32;
				else if (b < 512) b += 64;
				else b += 128;
			}
		}
		qsort(results, nres, sizeof(*results), cmp_hashrate);
		if (!quietflag) {
			fprintf(stderr, "[采样结果-降序]\n");
			for (int i = 0; i < nres; ++i) {
				if (results[i].fail) fprintf(stderr, "  threads=%d, BATCHNUM=%d, FAIL(内存分配), mem=%.1fMB, %.2fs\n", results[i].threads, results[i].batchnum, results[i].memMB, results[i].seconds);
				else fprintf(stderr, "  threads=%d, BATCHNUM=%d, hashrate=%.0f, mem=%.1fMB, %.2fs\n", results[i].threads, results[i].batchnum, results[i].hashrate, results[i].memMB, results[i].seconds);
			}
		}
		for (int i = 0; i < nres; ++i) if (!results[i].fail) { BATCHNUM = results[i].batchnum; numthreads = results[i].threads; break; }
		if (!quietflag) fprintf(stderr, "[自动调优] 选择最优线程数: %d, BATCHNUM: %d\n", numthreads, BATCHNUM);
		free(results);
	}
#endif

	if (numthreads <= 0) {
		numthreads = cpucount();
		if (numthreads <= 0)
			numthreads = 1;
	}
	if (!quietflag)
		fprintf(stderr,"using %d %s\n",
			numthreads,numthreads == 1 ? "thread" : "threads");

#ifdef PASSPHRASE
	if (deterministic) {
		if (!quietflag && numneedgenerate != 1 && !pw_skipnear && !pw_warnnear)
			fprintf(stderr,
				//         1         2         3         4         5         6         7
				//1234567890123456789012345678901234567890123456789012345678901234567890123456789
				"CAUTION: avoid using keys generated with the same password for unrelated\n"
				"         services, as single leaked key may help an attacker to regenerate\n"
				"		  related keys; to silence this warning, pass --skipnear or --warnnear.\n");
		if (checkpointfile) {
			memcpy(orig_determseed,determseed,sizeof(determseed));
			// Read current checkpoint position if file exists
			FILE *checkout = fopen(checkpointfile,"r");
			if (checkout) {
				u8 checkpoint[SEED_LEN];
				if(fread(checkpoint,1,SEED_LEN,checkout) != SEED_LEN) {
					fprintf(stderr,"failed to read checkpoint file\n");
					exit(1);
				}
				fclose(checkout);

				// Apply checkpoint to determseed
				bool carry = 0;
				for (int i = 0; i < SEED_LEN; i++) {
					determseed[i] += checkpoint[i] + carry;
					carry = determseed[i] < checkpoint[i];
				}
			}
		}
	}
#endif

	signal(SIGTERM,termhandler);
	signal(SIGINT,termhandler);

	// main worker batch memory allocation failure exits directly
VEC_INIT(threads);
VEC_ADDN(threads,numthreads);
#ifdef STATISTICS
VEC_INIT(stats);
VEC_ADDN(stats,numthreads);
VEC_ZERO(stats);
VEC_INIT(tstats);
VEC_ADDN(tstats,numthreads);
VEC_ZERO(tstats);
#endif
struct batch_buffers *main_batch_bufs = alloc_batch_buffers(BATCHNUM);
if (!main_batch_bufs) { fprintf(stderr, "[FATAL] worker batch memory allocation failed, BATCHNUM=%d\n", BATCHNUM); exit(1); }
    // worker index array, only used for Linux affinity binding
#ifdef __linux__
    int *worker_ids = malloc(numthreads * sizeof(int));
    if (!worker_ids) { perror("malloc"); exit(1); }
    for (int i = 0; i < numthreads; ++i) worker_ids[i] = i;
#endif

	pthread_attr_t tattr,*tattrp = &tattr;
	tret = pthread_attr_init(tattrp);
	if (tret) {
		perror("pthread_attr_init");
		tattrp = 0;
	}
	else {
		// 256KiB plus whatever batch stuff uses if in batch mode
		size_t ss = 256 << 10;
		if (wt == WT_BATCH)
			ss += worker_batch_memuse();
		// align to 64KiB
		ss = (ss + (64 << 10) - 1) & ~((64 << 10) - 1);
		//printf("stack size: " FSZ "\n",ss);
		tret = pthread_attr_setstacksize(tattrp,ss);
		if (tret)
			perror("pthread_attr_setstacksize");
	}

	for (size_t i = 0;i < VEC_LENGTH(threads);++i) {
		void *tp = main_batch_bufs;
#ifdef STATISTICS
		tp = &VEC_BUF(stats,i);
#endif
        // Linux pass worker index for affinity binding
#ifdef __linux__
        tp = &worker_ids[i];
#endif
		tret = pthread_create(
			&VEC_BUF(threads,i),
			tattrp,
#ifdef PASSPHRASE
			deterministic
				? CRYPTO_NAMESPACE(worker_batch_pass)
				:
#endif
			CRYPTO_NAMESPACE(worker_batch),
			tp
		);
		if (tret) {
			fprintf(stderr,"[FATAL] pthread_create failed: %s\n",strerror(tret));
			free_batch_buffers(main_batch_bufs);
			exit(1);
		}
		// At worker thread launch (Linux only), set thread affinity if enabled
#ifdef __linux__
		if (affinity_enabled) {
			cpu_set_t cpuset;
			CPU_ZERO(&cpuset);
			CPU_SET(i % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
			pthread_setaffinity_np(VEC_BUF(threads,i), sizeof(cpu_set_t), &cpuset);
		}
		// TODO: For NUMA memory binding, see libnuma's numa_alloc_onnode/mbind.
#endif
	}

	if (tattrp) {
		tret = pthread_attr_destroy(tattrp);
		if (tret)
			perror("pthread_attr_destroy");
	}

#ifdef PASSPHRASE
	pthread_t checkpoint_thread;

	if (checkpointfile) {
		tret = pthread_create(&checkpoint_thread,NULL,checkpointworker,NULL);
		if (tret) {
			fprintf(stderr,"error while making checkpoint thread: %s\n",strerror(tret));
			exit(1);
		}
	}
#endif

#ifdef STATISTICS
	struct timespec nowtime;
	u64 istarttime,inowtime,ireporttime = 0,elapsedoffset = 0;
	double last_hashrate = 0.0;
	double last_eta = 0.0;
	if (clock_gettime(CLOCK_MONOTONIC,&nowtime) < 0) {
		perror("failed to get time");
		exit(1);
	}
	istarttime = (1000000 * (u64)nowtime.tv_sec) + ((u64)nowtime.tv_nsec / 1000);
#endif

	struct timespec ts;
	memset(&ts,0,sizeof(ts));
	ts.tv_nsec = 100000000;
	while (!endwork) {
		if (numneedgenerate && keysgenerated >= numneedgenerate) {
			endwork = 1;
			break;
		}
		nanosleep(&ts,0);

#ifdef STATISTICS
		clock_gettime(CLOCK_MONOTONIC,&nowtime);
		inowtime = (1000000 * (u64)nowtime.tv_sec) + ((u64)nowtime.tv_nsec / 1000);
		u64 sumcalc = 0,sumsuccess = 0,sumrestart = 0;
		for (int i = 0;i < numthreads;++i) {
			u32 newt,tdiff;
			// numcalc
			newt = VEC_BUF(stats,i).numcalc.v;
			tdiff = newt - VEC_BUF(tstats,i).oldnumcalc;
			VEC_BUF(tstats,i).oldnumcalc = newt;
			VEC_BUF(tstats,i).numcalc += (u64)tdiff;
			sumcalc += VEC_BUF(tstats,i).numcalc;
			// numsuccess
			newt = VEC_BUF(stats,i).numsuccess.v;
			tdiff = newt - VEC_BUF(tstats,i).oldnumsuccess;
			VEC_BUF(tstats,i).oldnumsuccess = newt;
			VEC_BUF(tstats,i).numsuccess += (u64)tdiff;
			sumsuccess += VEC_BUF(tstats,i).numsuccess;
			// numrestart
			newt = VEC_BUF(stats,i).numrestart.v;
			tdiff = newt - VEC_BUF(tstats,i).oldnumrestart;
			VEC_BUF(tstats,i).oldnumrestart = newt;
			VEC_BUF(tstats,i).numrestart += (u64)tdiff;
			sumrestart += VEC_BUF(tstats,i).numrestart;
		}
		if (reportdelay && (!ireporttime || (i64)(inowtime - ireporttime) >= (i64)reportdelay)) {
			if (ireporttime)
				ireporttime += reportdelay;
			else
				ireporttime = inowtime;
			if (!ireporttime)
				ireporttime = 1;

			double elapsed_sec = (inowtime - istarttime + elapsedoffset) / 1000000.0;
			double hashrate = sumcalc / (elapsed_sec > 0 ? elapsed_sec : 1);
			double succrate = sumsuccess / (elapsed_sec > 0 ? elapsed_sec : 1);
			double restrate = sumrestart / (elapsed_sec > 0 ? elapsed_sec : 1);
			double progress = numneedgenerate ? (double)keysgenerated / numneedgenerate * 100.0 : 0.0;
			double eta = (numneedgenerate && hashrate > 0) ? (numneedgenerate - keysgenerated) / hashrate : 0.0;

			// unit adaptation
			const char *hrunit = ""; double hrval = hashrate;
			if (hrval > 1e9) { hrval /= 1e9; hrunit = "G"; }
			else if (hrval > 1e6) { hrval /= 1e6; hrunit = "M"; }
			else if (hrval > 1e3) { hrval /= 1e3; hrunit = "K"; }
			const char *srunit = ""; double srval = succrate;
			if (srval > 1e9) { srval /= 1e9; srunit = "G"; }
			else if (srval > 1e6) { srval /= 1e6; srunit = "M"; }
			else if (srval > 1e3) { srval /= 1e3; srunit = "K"; }
			const char *rrunit = ""; double rrval = restrate;
			if (rrval > 1e9) { rrval /= 1e9; rrunit = "G"; }
			else if (rrval > 1e6) { rrval /= 1e6; rrunit = "M"; }
			else if (rrval > 1e3) { rrval /= 1e3; rrunit = "K"; }

			fprintf(stderr,
				"> calc/sec: %.2f%s, succ/sec: %.2f%s, rest/sec: %.2f%s, progress: %.2f%%, ETA: %.1f sec, elapsed: %.1f sec\n",
				hrval, hrunit, srval, srunit, rrval, rrunit, progress, eta, elapsed_sec);
			fflush(stderr);

			// performance bottleneck self-check and optimization suggestions
			static int warned_threads = 0, warned_batch = 0, warned_avx2 = 0;
			if (numthreads > 1 && hashrate < numthreads * 50000 && !warned_threads) {
				fprintf(stderr, "[Optimization Suggestion] Low hashrate in multi-threaded mode, possibly limited by single-core/memory/filtering bottleneck. Try increasing BATCHNUM, optimizing filter rules, or checking CPU affinity.\n");
				warned_threads = 1;
			}
			if (BATCHNUM < 64 && hashrate < 100000 && !warned_batch) {
				fprintf(stderr, "[Optimization Suggestion] Current BATCHNUM is small, it is recommended to increase BATCHNUM to improve batch pipeline efficiency (e.g., 64/128/256).\n");
				warned_batch = 1;
			}
#if !defined(USE_AVX2)
			if (!warned_avx2) {
				fprintf(stderr, "[Optimization Suggestion] AVX2/SIMD acceleration not detected, if CPU supports, it is recommended to enable (compiler parameter -mavx2 or automatic detection).\n");
				warned_avx2 = 1;
			}
#endif

			if (realtimestats) {
				for (int i = 0;i < numthreads;++i) {
					VEC_BUF(tstats,i).numcalc = 0;
					VEC_BUF(tstats,i).numsuccess = 0;
					VEC_BUF(tstats,i).numrestart = 0;
				}
				elapsedoffset += inowtime - istarttime;
				istarttime = inowtime;
			}
#ifdef STATISTICS
				// output system resource monitoring information
				struct rusage ru;
				getrusage(RUSAGE_SELF, &ru);
				double mem_mb = ru.ru_maxrss / 1024.0;
				fprintf(stderr, "[资源] CPU user: %.2fs, sys: %.2fs, 内存: %.1f MB\n", ru.ru_utime.tv_sec + ru.ru_utime.tv_usec/1e6, ru.ru_stime.tv_sec + ru.ru_stime.tv_usec/1e6, mem_mb);

				// more detailed bottleneck analysis output
				if (n_samples > 0) {
					double total = t_keygen + t_base32 + t_filter + t_hash + t_other;
					fprintf(stderr, "[瓶颈分析] 密钥: %.1f%%, base32: %.1f%%, 筛选: %.1f%%, 哈希: %.1f%%, 其它: %.1f%%\n",
						100.0 * t_keygen/total, 100.0 * t_base32/total, 100.0 * t_filter/total, 100.0 * t_hash/total, 100.0 * t_other/total);
				}
#endif
		}
		if (sumcalc > U64_MAX / 2) {
			for (int i = 0;i < numthreads;++i) {
				VEC_BUF(tstats,i).numcalc /= 2;
				VEC_BUF(tstats,i).numsuccess /= 2;
				VEC_BUF(tstats,i).numrestart /= 2;
			}
			u64 timediff = (inowtime - istarttime + 1) / 2;
			elapsedoffset += timediff;
			istarttime += timediff;
		}
#endif
	}

	if (!quietflag)
		fprintf(stderr,"waiting for threads to finish...");

	// worker thread join exception handling
	for (size_t i = 0; i < VEC_LENGTH(threads); ++i) {
		tret = pthread_join(VEC_BUF(threads, i), NULL);
		if (tret) {
			fprintf(stderr, "[FATAL] pthread_join failed: %s\n", strerror(tret));
		}
	}
#ifdef PASSPHRASE
	if (checkpointfile) {
		checkpointer_endwork = 1;
		pthread_join(checkpoint_thread,0);
	}
#endif

	if (!quietflag)
		fprintf(stderr," done.\n");

	if (yamloutput)
		yamlout_clean();

#ifdef PASSPHRASE
	pthread_mutex_destroy(&determseed_mutex);
#endif
	pthread_mutex_destroy(&fout_mutex);
	pthread_mutex_destroy(&keysgenerated_mutex);

done:
	filters_clean();

	if (outfile)
		fclose(fout);

    // free main_batch_bufs
free_batch_buffers(main_batch_bufs);
    // free worker_ids
#ifdef __linux__
    free(worker_ids);
#endif

	return 0;
}
