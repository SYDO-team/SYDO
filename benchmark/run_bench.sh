#!/bin/sh
set -eu
export LC_ALL=C
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
param=160f
impl=ref
rounds=200
component_rounds=
warmup=50
cpu=0
compiler=gcc
output=
build=
baseline=
profile=0
bmi2=${BMI2:-1}
components=0
memory=0
mode=all
while [ "$#" -gt 0 ]; do
    if [ "$1" != --help ] && [ "$#" -lt 2 ]; then
        printf 'missing value for %s\n' "$1" >&2
        exit 2
    fi
    case "$1" in
        --param) param=$2;;
        --bmi2) bmi2=$2;;
        --impl) impl=$2;;
        --rounds) rounds=$2;;
        --component-rounds) component_rounds=$2;;
        --warmup) warmup=$2;;
        --cpu) cpu=$2;;
        --cc) compiler=$2;;
        --out) output=$2;;
        --build-dir) build=$2;;
        --baseline-csv) baseline=$2;;
        --profile) profile=$2;;
        --components) components=$2;;
        --memory) memory=$2;;
        --mode) mode=$2;;
        --help) printf '%s\n' 'run_bench.sh [--param 160f|160s|256f|256s|512f|512s] [--impl ref|avx2] [--rounds 200] [--component-rounds 200] [--warmup 50] [--cpu 0] [--cc gcc] [--bmi2 0|1] --out DIRECTORY [--build-dir DIRECTORY] [--baseline-csv FILE] [--profile 0|1] [--components 0|1] [--memory 0|1] [--mode all|components|memory]'; exit 0;;
        *) printf 'unknown option: %s\n' "$1" >&2; exit 2;;
    esac
    shift 2
done
[ -n "$component_rounds" ] || component_rounds=$rounds
case "$mode" in
    all) target=benchmark;;
    components) target=components; components=1;;
    memory) target=memory; memory=1;;
    *) printf '%s\n' '--mode must be all, components or memory' >&2; exit 2;;
esac
if [ "$mode" != all ] && { [ "$profile" != 0 ] || [ -n "$baseline" ]; }; then
    printf '%s\n' 'profiling and runtime acceptance require --mode all' >&2
    exit 2
fi
case "$bmi2" in 0|1) ;; *) printf '%s\n' '--bmi2 must be 0 or 1' >&2; exit 2;; esac
case "$profile" in 0|1) ;; *) printf '%s\n' '--profile must be 0 or 1' >&2; exit 2;; esac
case "$components" in 0|1) ;; *) printf '%s\n' '--components must be 0 or 1' >&2; exit 2;; esac
case "$memory" in 0|1) ;; *) printf '%s\n' '--memory must be 0 or 1' >&2; exit 2;; esac
if [ "$profile" = 1 ] && [ "$memory" = 1 ]; then
    printf '%s\n' 'collect memory data with profiling disabled' >&2
    exit 2
fi
if [ "$profile" = 1 ] && [ -n "$baseline" ]; then
    printf '%s\n' 'collect profiling data separately from runtime acceptance' >&2
    exit 2
fi
[ -n "$output" ] || { printf '%s\n' '--out must specify a result directory outside the source tree' >&2; exit 2; }
[ -n "$build" ] || build="$root/../sydo-build/$param-$impl"
if [ "$profile" = 1 ]; then build="$build-profile"; fi
mkdir -p "$output" "$build"
output=$(CDPATH= cd -- "$output" && pwd)
build=$(CDPATH= cd -- "$build" && pwd)
case "$output/" in "$root/"*) printf '%s\n' 'result directory must be outside the source tree' >&2; exit 2;; esac
case "$build/" in "$root/"*) printf '%s\n' 'build directory must be outside the source tree' >&2; exit 2;; esac
command -v taskset >/dev/null
command -v flock >/dev/null
exec 9>"${TMPDIR:-/tmp}/sydo-benchmark-$(id -u).lock"
flock 9
{
    printf 'parameter=%s\nimplementation=%s\nrounds=%s\nwarmup=%s\ncpu=%s\n' "$param" "$impl" "$rounds" "$warmup" "$cpu"
    printf 'profile=%s\nmode=%s\ncomponent_rounds=%s\n' "$profile" "$mode" "$component_rounds"
    if [ "$impl" = avx2 ]; then
        if [ "$bmi2" = 1 ]; then printf '%s\n' 'isa=AVX2,AES,PCLMULQDQ,SSSE3,BMI2'; else printf '%s\n' 'isa=AVX2,AES,PCLMULQDQ,SSSE3'; fi
    else printf '%s\n' 'isa=portable C'; fi
    printf 'bmi2=%s\n' "$bmi2"
    printf 'compiler='; "$compiler" --version | head -1
    printf 'timestamp_utc='; date -u '+%Y-%m-%dT%H:%M:%SZ'
    printf 'source_revision='
    if top=$(git -C "$root" rev-parse --show-toplevel 2>/dev/null) && [ "$top" = "$root" ] && revision=$(git -C "$root" rev-parse --verify HEAD 2>/dev/null); then
        printf '%s\n' "$revision"
    else printf '%s\n' uncommitted; fi
    uname -smr
    lscpu | sed -n '/Model name:/p'
    for setting in /sys/devices/system/cpu/cpufreq/boost /sys/devices/system/cpu/intel_pstate/no_turbo \
        /sys/devices/system/cpu/cpu"$cpu"/cpufreq/scaling_driver \
        /sys/devices/system/cpu/cpu"$cpu"/cpufreq/scaling_governor \
        /sys/devices/system/cpu/cpu"$cpu"/cpufreq/scaling_min_freq \
        /sys/devices/system/cpu/cpu"$cpu"/cpufreq/scaling_max_freq; do
        if [ -r "$setting" ]; then printf '%s=' "${setting##*/}"; cat "$setting"; fi
    done
} > "$output/metadata.txt"
(cd "$root" && find . -type f ! -path './.git/*' ! -path '*/__pycache__/*' -print | sort | xargs sha256sum) > "$output/sources.sha256"
configuration=$(printf '%s\n' "$compiler" "$("$compiler" -dumpfullversion)" "$param" "$impl" "$profile" "${CFLAGS:-default}" "${CPPFLAGS:-default}" "${LDFLAGS:-default}" "${NGCC_CFLAGS:-default}" "$mode" "$bmi2")
force=
if [ ! -f "$build/benchmark.config" ] || [ "$configuration" != "$(cat "$build/benchmark.config")" ]; then force=-B; fi
taskset -c "$cpu" make -C "$root" -j1 $force CC="$compiler" PARAM="$param" IMPL="$impl" BMI2="$bmi2" PROFILE="$profile" BUILD_DIR="$build" "$target" > "$output/build.log" 2>&1
printf '%s\n' "$configuration" > "$build/benchmark.config"
if [ "$mode" = all ]; then
{ printf 'cycle_source='; taskset -c "$cpu" "$build/bench" --cycle-source; } >> "$output/metadata.txt"
printf '%s\n' 'parameter,implementation,operation,rounds,mean_us,median_us,min_us,max_us,maxrss_kib,warmup,mean_cycles,mean_mcycles,cycle_source' > "$output/benchmark.csv"
for operation in keygen sign verify; do
    SYDO_PROFILE_OUT="$output/$operation.profile.csv" SYDO_BENCH_SAMPLES_OUT="$output/$operation-samples.csv" \
        taskset -c "$cpu" "$build/bench" "$operation" "$rounds" "$warmup" >> "$output/benchmark.csv"
done
fi
if [ "$components" = 1 ]; then
    taskset -c "$cpu" make -C "$root" -j1 CC="$compiler" PARAM="$param" IMPL="$impl" BMI2="$bmi2" PROFILE="$profile" BUILD_DIR="$build" components >> "$output/build.log" 2>&1
    printf '%s\n' 'component,rounds,work_items,mean_ns,median_ns,min_ns,max_ns,checksum' > "$output/components.csv"
    for component in $("$build/bench-components" --list); do
        taskset -c "$cpu" "$build/bench-components" "$component" "$component_rounds" "$warmup" >> "$output/components.csv"
    done
fi
if [ "$memory" = 1 ]; then
    taskset -c "$cpu" make -C "$root" -j1 CC="$compiler" PARAM="$param" IMPL="$impl" BMI2="$bmi2" BUILD_DIR="$build" memory >> "$output/build.log" 2>&1
    taskset -c "$cpu" "$build/test-memory-tracker" > "$output/memory-tracker.log"
    printf '%s\n' 'operation,mode,heap_requested_peak,heap_usable_peak,stack_peak,heap_requested_live,heap_usable_live,maxrss_kib' > "$output/memory.csv"
    for operation in keygen sign verify; do
        for memory_mode in stack rss; do
            taskset -c "$cpu" "$build/bench-memory" "$operation" "$memory_mode" >> "$output/memory.csv"
        done
    done
fi
if [ -n "$baseline" ]; then
    awk -F, 'BEGIN {OFS=","; print "parameter,implementation,operation,current_us,baseline_us,ratio,result"}
      NR==FNR {if(FNR>1) {key=$1 FS $2 FS $3; old[key]=$5; old_rounds[key]=$4; old_warmup[key]=$10} next}
      FNR>1 {key=$1 FS $2 FS $3; if(!(key in old)) {print $1,$2,$3,$5,"","","missing-baseline"; missing=1; next}
        if($4!=old_rounds[key] || $10=="" || $10!=old_warmup[key]) {print $1,$2,$3,$5,old[key],"","incompatible-rounds-or-warmup"; missing=1; next}
        ratio=$5/old[key]; result=($3=="keygen" ? "informational" : (ratio<=1.05 ? "pass" : "fail"));
        print $1,$2,$3,$5,old[key],ratio,result; if(result=="fail") failed=1}
      END {if(failed || missing) exit 1}' "$baseline" "$output/benchmark.csv" > "$output/comparison.csv" || { cat "$output/comparison.csv"; exit 1; }
fi
case "$mode" in
    all) cat "$output/benchmark.csv";;
    components) cat "$output/components.csv";;
    memory) cat "$output/memory.csv";;
esac
