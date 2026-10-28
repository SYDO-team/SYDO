#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$here
if [ ! -d "$root/Implementations" ]; then root=$(CDPATH= cd -- "$here/.." && pwd); fi
if [ ! -d "$root/Implementations" ] && [ ! -f "$root/Makefile" ]; then
    printf '%s\n' 'SYDO source or submission directory not found' >&2
    exit 2
fi
cpu=0
rounds=200
warmup=50
compiler=gcc
bmi2=1
output=
build=
memory=1
while [ "$#" -gt 0 ]; do
    if [ "$1" = --help ]; then
        printf '%s %s\n' "${0##*/}" '--out DIRECTORY [--build-dir DIRECTORY] [--cpu 0] [--rounds 200] [--warmup 50] [--cc gcc] [--bmi2 0|1] [--memory 0|1]'
        exit 0
    fi
    [ "$#" -ge 2 ] || { printf 'missing value for %s\n' "$1" >&2; exit 2; }
    case "$1" in
        --out) output=$2;;
        --build-dir) build=$2;;
        --cpu) cpu=$2;;
        --rounds) rounds=$2;;
        --warmup) warmup=$2;;
        --cc) compiler=$2;;
        --bmi2) bmi2=$2;;
        --memory) memory=$2;;
        *) printf 'unknown option: %s\n' "$1" >&2; exit 2;;
    esac
    shift 2
done
[ -n "$output" ] || { printf '%s\n' '--out is required' >&2; exit 2; }
[ -n "$build" ] || build="$root/../sydo-submission-build"
mkdir -p "$output" "$build"
output=$(CDPATH= cd -- "$output" && pwd)
build=$(CDPATH= cd -- "$build" && pwd)
case "$output/" in "$root/"*) printf '%s\n' 'results must be outside the package' >&2; exit 2;; esac
case "$build/" in "$root/"*) printf '%s\n' 'builds must be outside the package' >&2; exit 2;; esac
for implementation in Reference_Implementation Optimized_Implementation; do
    case "$implementation" in Reference_Implementation) impl=ref;; *) impl=avx2;; esac
    for param in 160f 160s 256f 256s 512f 512s; do
        name=$param-$impl
        source=$root
        if [ -d "$root/Implementations" ]; then source=$root/Implementations/$implementation/sydo_$param; fi
        "$source/benchmark/run_bench.sh" \
            --param "$param" --impl "$impl" --cc "$compiler" --cpu "$cpu" \
            --rounds "$rounds" --warmup "$warmup" --bmi2 "$bmi2" --memory "$memory" \
            --out "$output/$name" --build-dir "$build/$name"
    done
done
