# mkp224o - vanity address generator for ed25519 onion services

## PERFORMANCE NOTES

- **SIMD/AVX2/NEON:** All batch processing (keygen, base32 encoding, filtering, hashing) is designed for SIMD acceleration. AVX2 plug-in points are present for x86_64, and NEON stubs can be added for ARM. All batch buffers are 32-byte aligned for maximum SIMD throughput.
- **Batch Pipeline:** Key generation, encoding, filtering, and hashing are fully batchified. Batch size and thread count are autotuned at startup for optimal throughput, with user override available.
- **Cache and Memory Layout:** All batch buffers are allocated contiguously and aligned for cache efficiency. Per-thread statistics structures are padded to 64 bytes to avoid false sharing.
- **NUMA and CPU Affinity:** On Linux, worker threads can be pinned to specific CPU cores using `--affinity` or the `MKP224O_AFFINITY=1` environment variable. NUMA memory binding is documented and can be added with libnuma for large systems.
- **Autotune:** The program automatically benchmarks different (threads, batch size) pairs at startup and selects the best configuration. All autotune and performance statistics are reported in real time.
- **Lock-Free/Minimal Locking:** All statistics are per-thread and merged in the main thread, minimizing contention. Batch buffers are reused to avoid allocation overhead.
- **Prefetching and Vectorization:** Main loops are structured for easy vectorization and prefetching. SIMD plug-in points are clearly marked in the code for future hand-written vector code.
- **Cross-Platform:** All performance features have portable fallbacks. SIMD, affinity, and NUMA features are enabled only when supported by the platform and CPU.
- **Documentation:** All code and comments are in English. Each major file begins with a PERFORMANCE NOTES section summarizing its performance features and design.

---

## Build Instructions

### Linux (Debian/Ubuntu)

1. **Install dependencies:**
   ```bash
   sudo apt update
   sudo apt install gcc libc6-dev libsodium-dev make autoconf
   ```
2. **Generate configure script (if not present):**
   ```bash
   ./autogen.sh
   ```
3. **Configure the build:**
   ```bash
   ./configure
   # For AVX2 SIMD acceleration (recommended on x86_64):
   ./configure --enable-amd64-51-30k
   ```
4. **Build the project:**
   ```bash
   make
   ```

### macOS

1. **Install dependencies (using Homebrew):**
   ```bash
   brew install libsodium autoconf
   ```
2. **Generate configure script (if not present):**
   ```bash
   ./autogen.sh
   ```
3. **Configure the build:**
   ```bash
   ./configure
   ```
4. **Build the project:**
   ```bash
   make
   ```

### Notes
- On BSD or other UNIX-like systems, you may need to specify include/library paths:
  ```bash
  ./configure CPPFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
  ```
- For SIMD/AVX2/NEON support, ensure your compiler and CPU support the relevant instruction sets.
- For PCRE2 regex filtering, add `-DPCRE2FILTER` to CFLAGS and link with `-lpcre2-8`.

---

## Application / Usage Examples

### Basic Usage

Generate onion addresses matching a filter:
```bash
./mkp224o neko
```

Specify output directory:
```bash
./mkp224o -d output_dir neko
```

Load filters from a file:
```bash
./mkp224o -f filters.txt
```

Show all available options:
```bash
./mkp224o -h
```

### Batch, SIMD, NUMA, and Affinity Options

- **Enable statistics output:**
  ```bash
  ./mkp224o -s neko
  ```
- **Set batch size and thread count manually:**
  ```bash
  ./mkp224o --batch 64 --threads 8 neko
  ```
- **Enable CPU affinity (Linux):**
  ```bash
  MKP224O_AFFINITY=1 ./mkp224o neko
  ```
- **Enable NUMA memory binding (Linux, if compiled with libnuma):**
  ```bash
  MKP224O_NUMA=1 ./mkp224o neko
  ```
- **Enable AVX2 SIMD (if supported):**
  ```bash
  ./configure --enable-amd64-51-30k
  make
  ./mkp224o neko
  ```

### Advanced Filtering

- **Glob pattern filtering:**
  ```bash
  ./mkp224o --glob ab*cd?e
  ```
- **Regex filtering (PCRE2):**
  ```bash
  ./mkp224o --regex '^ab.*cd$' 'foo[0-9]{2}'
  ```

### Deterministic Mode and Checkpoint/Resume

- **Deterministic (passphrase) mode with checkpointing:**
  ```bash
  ./mkp224o --passphrase "your pass" --checkpoint myprogress.chk neko
  ```
- **Resume from checkpoint:**
  ```bash
  ./mkp224o --passphrase "your pass" --checkpoint myprogress.chk neko
  ```

---

## More Information

- See [OPTIMISATION.txt](./OPTIMISATION.txt) for detailed performance tips and tuning advice.
- All code and documentation are in English and follow a unified, professional style.
- For questions, see the FAQ section below or open an issue on GitHub.

---

## FAQ and other useful info

* How do I generate address?

  Once compiled, run it like `./mkp224o neko`, and it will try creating
  keys for onions starting with "neko" in this example; use `./mkp224o
  -d nekokeys neko` to not litter current directory and put all
  discovered keys in directory named "nekokeys".

* How do I make tor use generated keys?

  Copy key folder (though technically only `hs_ed25519_secret_key` is required)
  to where you want your service keys to reside:

  ```bash
  sudo cp -r neko54as6d54....onion /var/lib/tor/nekosvc
  ```

  You may need to adjust ownership and permissions:

  ```bash
  sudo chown -R tor: /var/lib/tor/nekosvc
  sudo chmod -R u+rwX,og-rwx /var/lib/tor/nekosvc
  ```

  Then edit `torrc` and add new service with that folder.\
  After reload/restart tor should pick it up.

* How to generate addresses with `0-1` and `8-9` digits?

  Onion addresses use base32 encoding which does not include `0,1,8,9`
  numbers.\
  So no, that's not possible to generate these, and mkp224o tries to
  detect invalid filters containing them early on.

* How long is it going to take?

  Because of probablistic nature of brute force key generation, and
  varience of hardware it's going to run on, it's hard to make promisses
  about how long it's going to take, especially when the most of users
  want just a few keys.\
  See [this issue][#27] for very valuable discussion about this.\
  If your machine is powerful enough, 6 character prefix shouldn't take
  more than few tens of minutes, if using batch mode (read
  [OPTIMISATION.txt][OPTIMISATION]) 7 characters can take hours
  to days.\
  No promisses though, it depends on pure luck.

* Will this work with onionbalance?

  It appears that onionbalance supports loading usual
  `hs_ed25519_secret_key` key so it should work.

* Is there a docker image?

  Yes, if you do not wish to compile mkp224o yourself, you can use
  the `ghcr.io/cathugger/mkp224o` image like so:

  ```bash
  docker run --rm -it -v $PWD:/keys ghcr.io/cathugger/mkp224o:master -d /keys neko
  ```

---

## Acknowledgements & Legal

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software to the
public domain worldwide. This software is distributed without any
warranty.
You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see [CC0][].

* `keccak.c` is based on [Keccak-more-compact.c][keccak.c]
* `ed25519/{ref10,amd64-51-30k,amd64-64-24k}` are adopted from
  [SUPERCOP][]
* `ed25519/ed25519-donna` adopted from [ed25519-donna][]
* Idea used in `worker_fast()` is stolen from [horse25519][]
* base64 routines and initial YAML processing work contributed by
  Alexander Khristoforov (heios at protonmail dot com)
* Passphrase-based generation code and idea used in `worker_batch()`
  contributed by [foobar2019][]

[OPTIMISATION]: ./OPTIMISATION.txt
[#27]: https://github.com/cathugger/mkp224o/issues/27
[keccak.c]: https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-more-compact.c
[CC0]: https://creativecommons.org/publicdomain/zero/1.0/
[SUPERCOP]: https://bench.cr.yp.to/supercop.html
[ed25519-donna]: https://github.com/floodyberry/ed25519-donna
[horse25519]: https://github.com/Yawning/horse25519
[foobar2019]: https://github.com/foobar2019
[^1]: https://spec.torproject.org/rend-spec/index.html
[^2]: https://gitlab.torproject.org/tpo/core/torspec/-/raw/main/attic/text_formats/rend-spec-v3.txt
