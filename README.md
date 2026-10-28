# SYDO 1.1

SYDO is a post-quantum signature scheme based on the hardness of the syndrome
decoding (SD) problem. This repository contains two implementations of SYDO,
both with the NGCC signature API:

- `ref`: the reference implementation, in ISO C without platform-specific
  instruction set extensions;
- `avx2`: the AVX2-optimized implementation for x86-64, using AVX2, AES-NI,
  PCLMULQDQ and SSSE3.

The updated specification for SYDO v1.1 will be published in the near future.

All commands below are for **Linux**.

## Quick start

Build all six parameter sets with both implementations and check their KATs:

```sh
git clone https://github.com/SYDO-team/SYDO.git
cd SYDO
python3 tools/kat.py --out ../sydo-kat
```

It prints one line per implementation, from `160f-ref: KAT passed` to
`512s-avx2: KAT passed` (12 lines).

## Requirements

- GCC (or another C11 compiler), GNU Make
- Python 3.8 or newer (for the scripts in `tools/`)
- `taskset` and `flock` (package `util-linux`, installed by default on most distributions)
- `avx2` only: an x86-64 CPU with AVX2, AES-NI, PCLMULQDQ and SSSE3; BMI2 is used when available

On Debian or Ubuntu:

```sh
sudo apt install build-essential python3 util-linux
```

## Parameter sets

SYDO has six parameter sets: SYDO-160s, SYDO-160f, SYDO-256s, SYDO-256f,
SYDO-512s and SYDO-512f. The number is the classical security level in bits.
The short ("s") variants reduce signature size, while the fast ("f") variants
improve signing and verification time. In commands, a parameter
set is written without the prefix, e.g. `PARAM=160f`. Sizes in bytes, the same
for both implementations:

| Parameter set | `PARAM` | NGCC instance | \|sk\| | \|pk\| | \|sig\| |
|---|---|---|---:|---:|---:|
| SYDO-160s | `160s` | `sydo_160s` | 174 | 80 | 5428 |
| SYDO-160f | `160f` | `sydo_160f` | 174 | 80 | 6724 |
| SYDO-256s | `256s` | `sydo_256s` | 278 | 128 | 14444 |
| SYDO-256f | `256f` | `sydo_256f` | 278 | 128 | 17604 |
| SYDO-512s | `512s` | `sydo_512s` | 534 | 246 | 56672 |
| SYDO-512f | `512f` | `sydo_512f` | 534 | 246 | 67716 |

## Build

```sh
make PARAM=<parameter set> IMPL=<ref|avx2> [target]
```

For example, `make PARAM=256s IMPL=avx2`.

| Variable | Values | Default |
|---|---|---|
| `PARAM` | `160f`, `160s`, `256f`, `256s`, `512f`, `512s` | `160f` |
| `IMPL` | `ref`, `avx2` | `ref` |
| `BMI2` | `1` (use BMI2), `0` (do not use BMI2) — `avx2` only | `1` |
| `CC` | C compiler | `gcc` |
| `BUILD_DIR` | output directory | `../sydo-build/<PARAM>-<IMPL>` |

| Target | What it does | Output in `BUILD_DIR` |
|---|---|---|
| *(none)* | build the library | `libsydo.a` |
| `kat` | build the NGCC KAT program (`KAT_SIG.c`) | `kat_sig` |
| `check` | build and run all tests | test programs |
| `benchmark` | build the benchmark program | `bench` |
| `clean` | delete the build outputs | |

Build outputs are written outside the source tree, to `../sydo-build/` by
default. Each parameter set and implementation has its own subdirectory.

## Tests

```sh
make PARAM=<parameter set> IMPL=<ref|avx2> check
```

For example, `make PARAM=256s IMPL=avx2 check`.

`check` verifies that the NGCC files in `third_party/ngcc/` and
the headers in `api/ngcc/` are identical to the official NGCC files (SHA-256).
It then runs
the tests for the primitives, Rijndael, hashing, the NGCC API, input
validation, allocation failures, the secret key and security checks. It
also checks that the official NGCC functions `pseudoXOF` and
`get_random_number` are called. Testing stops at the first failure.

## Known Answer Tests (KAT)

A KAT file is produced by the official NGCC program
`third_party/ngcc/KAT_SIG.c`. It contains ten records; each record has a seed,
a public key, a secret key, a message and a signature. The SHA-256 of the KAT
file for each parameter set is stored in `tests/kat.sha256`.

`tools/kat.py` does the whole check in one command:

1. builds the NGCC KAT program for the selected parameter set and implementation;
2. runs it to generate the KAT file;
3. compares the file's SHA-256 with `tests/kat.sha256`.

```sh
python3 tools/kat.py --out ../sydo-kat                             # all parameter sets, both implementations (12 KATs)
python3 tools/kat.py --param 256s --impl avx2 --out ../sydo-kat    # one parameter set and implementation
```

| Option | Meaning | Default |
|---|---|---|
| `--out DIR` | where the KAT files and logs are written; must be **outside** the repository | required |
| `--param` | `160f` … `512s`, or `all` | `all` |
| `--impl` | `ref`, `avx2`, or `both` | `both` |
| `--build-dir DIR` | build directory | `../sydo-kat-build` |
| `--cc` | C compiler | `gcc` |
| `--cpu N` | CPU core to run on | `0` |
| `--bmi2 0/1` | use BMI2 in the `avx2` build | `1` |

For each implementation, the script prints `<parameter set>-<implementation>: KAT passed`
(for example `256s-avx2: KAT passed`). On a mismatch it prints
`KAT mismatch: <file>` and exits with status 1. Output layout:

```
../sydo-kat/256s-avx2/output/KAT_SIG_sydo_256s.txt   generated KAT file
../sydo-kat/256s-avx2/build.log                      build log
../sydo-kat/256s-avx2/kat.log                        KAT program log
```

`ref` and `avx2` produce identical KAT files.

To run the KAT program by hand instead:

```sh
make PARAM=160f IMPL=ref kat
mkdir -p ../sydo-kat-manual && cd ../sydo-kat-manual
../sydo-build/160f-ref/kat_sig            # writes output/KAT_SIG_sydo_160f.txt
sha256sum output/KAT_SIG_sydo_160f.txt    # compare with tests/kat.sha256
```

## Using the library

The NGCC API is declared in `api/ngcc/<parameter set>/SIG_AlgorithmInstance.h`:

| Function | Purpose |
|---|---|
| `sig_get_pk_len_bytes()`, `sig_get_sk_len_bytes()`, `sig_get_sn_len_bytes()` | key and signature sizes |
| `sig_keygen(pk, &pk_len, sk, &sk_len)` | generate a key pair |
| `sig_sign(sk, sk_len, m, m_len, sn, &sn_len)` | sign message `m` |
| `sig_verify(pk, pk_len, sn, sn_len, m, m_len)` | verify a signature |

Return values: `0` = success; `-1` = invalid input, or invalid signature for
`sig_verify`; `-2` = internal error (allocation or hash failure); `-3` =
random number generator failure.

Randomness comes from the NGCC DRNG. The application must define the global
`drng_algorithm` and seed it before calling `sig_keygen` or `sig_sign`:

```c
#include <stdio.h>
#include <stdlib.h>
#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;                      /* required by the NGCC API */

int main(void) {
    unsigned char seed[64] = {0};             /* use real entropy in practice */
    if (init_random_number(&drng_algorithm, seed, sizeof seed)) return 1;

    unsigned long long pk_len, sk_len, sn_len;
    unsigned char *pk = malloc(sig_get_pk_len_bytes());
    unsigned char *sk = malloc(sig_get_sk_len_bytes());
    unsigned char *sn = malloc(sig_get_sn_len_bytes());
    unsigned char msg[] = "hello";

    if (sig_keygen(pk, &pk_len, sk, &sk_len)) return 1;
    if (sig_sign(sk, sk_len, msg, sizeof msg - 1, sn, &sn_len)) return 1;
    int rc = sig_verify(pk, pk_len, sn, sn_len, msg, sizeof msg - 1);
    printf("%s: signature %llu bytes, verify = %d\n", ALGORITHM_INSTANCE, sn_len, rc);
    free(pk); free(sk); free(sn);
    return rc != 0;
}
```

Save it as `example.c` in the repository root, then build and run it:

```sh
make PARAM=160f IMPL=ref
gcc -Iapi/ngcc/160f -Ithird_party/ngcc example.c ../sydo-build/160f-ref/libsydo.a -o example
./example          # prints: sydo_160f: signature 6724 bytes, verify = 0
```

For another parameter set, change `160f` in all three places. For `avx2`, use
`IMPL=avx2` and `../sydo-build/<parameter set>-avx2/libsydo.a`.

`include/sydo.h` provides the same three operations with the randomness passed
in by the caller (`sydo_keygen_from_seed`, `sydo_sign_from_seed`,
`sydo_verify`), for tests or for applications that use their own random
number generator.

## Benchmarks

```sh
./tools/benchmark_all.sh --cpu 0 --rounds 200 --warmup 50 --out ../sydo-results                    # all 12 implementations
./benchmark/run_bench.sh --param 160f --impl avx2 --cpu 0 --out ../sydo-bench-160f-avx2  # one implementation
```

Key generation, signing and verification each run on one pinned CPU core.
Results are the arithmetic mean of 200 calls after 50 warm-up calls. Results directories must be outside the
repository. Each results directory contains:

| File | Content |
|---|---|
| `benchmark.csv` | running time of KeyGen, Sign and Verify (mean, median, min, max) |
| `metadata.txt` | CPU, compiler and settings |
| `build.log` | build log |

`./benchmark/run_bench.sh --help` lists all options.

### Results

The following results were measured using the setup below.

| Item | Reference implementation | AVX2-optimized implementation |
|---|---|---|
| Language | ISO C11 | ISO C11 |
| Compiler | GCC 14.3.0 | GCC 14.3.0 |
| Instruction set extensions | No platform-specific extensions | AVX2, AES-NI, PCLMULQDQ, SSSE3, BMI2 |
| Compiler flags | `-O3 -flto` | `-O3 -flto` |
| Processor | AMD Ryzen 9 3900X, single core | AMD Ryzen 9 3900X, single core |
| Clock frequency | 2.2–3.8 GHz configured range, `schedutil` | 2.2–3.8 GHz configured range, `schedutil` |
| Memory | 64 GB | 64 GB |
| Operating system | Ubuntu 22.04 | Ubuntu 22.04 |
| Library | None | None |

Reference implementation:

| Instance | KeyGen (µs) | KeyGen (Mcyc) | Sign (ms) | Sign (Mcyc) | Verify (ms) | Verify (Mcyc) |
|---|---:|---:|---:|---:|---:|---:|
| SYDO-160f | 41.482 | 0.158 | 30.499 | 115.677 | 27.634 | 104.812 |
| SYDO-160s | 41.317 | 0.157 | 75.171 | 285.115 | 69.275 | 262.752 |
| SYDO-256f | 69.405 | 0.263 | 71.355 | 270.641 | 63.085 | 239.273 |
| SYDO-256s | 69.255 | 0.263 | 176.508 | 669.473 | 168.309 | 638.374 |
| SYDO-512f | 143.779 | 0.545 | 270.191 | 1024.802 | 231.032 | 876.278 |
| SYDO-512s | 143.406 | 0.544 | 711.531 | 2698.755 | 639.556 | 2425.762 |

AVX2-optimized implementation:

| Instance | KeyGen (µs) | KeyGen (Mcyc) | Sign (ms) | Sign (Mcyc) | Verify (ms) | Verify (Mcyc) |
|---|---:|---:|---:|---:|---:|---:|
| SYDO-160f | 11.012 | 0.042 | 3.497 | 13.264 | 3.231 | 12.254 |
| SYDO-160s | 11.182 | 0.043 | 16.173 | 61.343 | 13.993 | 53.073 |
| SYDO-256f | 19.852 | 0.075 | 8.021 | 30.424 | 7.557 | 28.664 |
| SYDO-256s | 19.960 | 0.076 | 34.555 | 131.064 | 33.848 | 128.381 |
| SYDO-512f | 43.308 | 0.164 | 52.814 | 200.319 | 50.602 | 191.929 |
| SYDO-512s | 43.690 | 0.166 | 248.391 | 942.120 | 225.014 | 853.453 |

## NGCC submission package

```sh
python3 tools/make_submission.py --out ../SYDO-NGCC --cpu 0
```

The script:

- creates one standalone directory for each of the 12 implementations under
  `Implementations/Reference_Implementation/sydo_<parameter set>/` and
  `Implementations/Optimized_Implementation/sydo_<parameter set>/`;
- builds each directory and checks its KAT against `tests/kat.sha256`;
- requires the `ref` and `avx2` KAT files to be identical;
- writes the KAT files to `Test_Vectors/`;
- writes `../SYDO-NGCC.zip` and `SHA256SUMS`.

`--out` must be a directory that does not exist yet. Each package directory
works on its own with `make`, `python3 tools/kat.py --out <dir>` and
`./benchmark/run_bench.sh --out <dir>`.

## Source layout

```
api/ngcc/             NGCC API: SIG_AlgorithmInstance.c and one header per parameter set
include/sydo.h        core API with caller-supplied randomness
src/                  KeyGen, Sign, Verify, BAVC, VOLE, RSD constraints, hash functions
src/parameters/       parameter definitions (160.h, 256.h, 512.h)
src/ref/, src/avx2/   implementation-specific cipher, matrix and field code
third_party/ngcc/     official NGCC files, unmodified: pseudoXOF, DRNG, KAT program
tests/                tests, NGCC file hashes (check_ngcc.sh), KAT hashes (kat.sha256)
benchmark/            benchmark programs and run_bench.sh
tools/                kat.py, benchmark_all.sh, make_submission.py
```
