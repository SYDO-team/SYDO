#!/usr/bin/env python3
"""Create standalone NGCC implementations, verified test vectors and a ZIP archive."""

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True

from kat import (ROOT, PARAMETERS, IMPLEMENTATIONS, outside, expected_hashes,
                 check_vector, build_kat, serial_lock)


def copy_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def source_files(source, directory, suffixes):
    root = source / directory
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if (path.is_file() and not path.is_symlink() and path.suffix in suffixes and
                all(not part.startswith(".") and part != "__pycache__" for part in relative.parts)):
            yield path


def instance(source, target, param, impl):
    target.mkdir(parents=True)
    for directory in ("include", "benchmark", "tests", "third_party/ngcc"):
        for path in source_files(source, directory, (".c", ".h", ".sh", ".sha256")):
            if path.name not in ("check_ngcc.sh", "KAT_SIG.c"):
                copy_file(path, target / path.relative_to(source))
    for path in source_files(source, "src", (".c", ".h")):
        if path.parent.name not in IMPLEMENTATIONS or path.parent.name == impl:
            copy_file(path, target / path.relative_to(source))
    copy_file(source / "api/ngcc/SIG_AlgorithmInstance.c", target / "SIG_AlgorithmInstance.c")
    copy_file(source / "api/ngcc" / param / "SIG_AlgorithmInstance.h", target / "SIG_AlgorithmInstance.h")
    copy_file(source / "third_party/ngcc/KAT_SIG.c", target / "KAT_SIG.c")
    makefile = (source / "Makefile").read_text()
    makefile = makefile.replace("PARAM ?= 160f", "PARAM ?= " + param)
    makefile = makefile.replace("IMPL ?= ref", "IMPL ?= " + impl)
    makefile = makefile.replace("-Iapi/ngcc/$(PARAM)", "-I.")
    makefile = makefile.replace("api/ngcc/SIG_AlgorithmInstance.c", "SIG_AlgorithmInstance.c")
    makefile = makefile.replace("third_party/ngcc/KAT_SIG.c", "KAT_SIG.c")
    guards = (
        "ifneq ($(PARAM)," + param + ")\n$(error This directory builds PARAM=" + param + ")\nendif\n"
        "ifneq ($(IMPL)," + impl + ")\n$(error This directory builds IMPL=" + impl + ")\nendif\n\n"
    )
    makefile = makefile.replace("BMI2 ?= 1", guards + "BMI2 ?= 1")
    (target / "Makefile").write_text(makefile)
    bench = target / "benchmark/run_bench.sh"
    bench.write_text(bench.read_text().replace("param=160f\n", "param=" + param + "\n")
                     .replace("impl=ref\n", "impl=" + impl + "\n"))
    checker = (source / "tests/check_ngcc.sh").read_text()
    lines = []
    for line in checker.splitlines():
        if "api/ngcc/" in line:
            if "/" + param + "/" not in line:
                continue
            line = line.replace("api/ngcc/" + param + "/", "")
        line = line.replace("third_party/ngcc/KAT_SIG.c", "KAT_SIG.c")
        lines.append(line)
    (target / "tests/check_ngcc.sh").write_text("\n".join(lines) + "\n")
    (target / "tests/check_ngcc.sh").chmod(0o755)
    kat = (source / "tools/kat.py").read_text()
    kat = kat.replace('default="all"', 'default="' + param + '"')
    kat = kat.replace('default="both"', 'default="' + impl + '"')
    kat = "\n".join(
        ('PARAMETERS = ("' + param + '",)') if line.startswith("PARAMETERS = ") else
        ('IMPLEMENTATIONS = ("' + impl + '",)') if line.startswith("IMPLEMENTATIONS = ") else line
        for line in kat.splitlines()) + "\n"
    (target / "tools").mkdir()
    (target / "tools/kat.py").write_text(kat)
    (target / "README.md").write_text(
        "# SYDO " + param + " (" + impl + ")\n\n"
        "Standalone C11 implementation. NGCC API: `SIG_AlgorithmInstance.h`.\n\n"
        "```sh\nmake -j1 CC=gcc\n"
        "python3 tools/kat.py --out ../kat-" + param + "-" + impl + "\n"
        "./benchmark/run_bench.sh --cpu 0 --rounds 200 --warmup 50 "
        "--out ../results-" + param + "-" + impl + "\n```\n\n"
        "KAT checks ten records generated with the NGCC KAT driver. Benchmark reports the mean of 200 calls "
        "after 50 warm-up calls, on one CPU.\n"
        "Outputs: `benchmark.csv` (time).\n"
        "See the package README for requirements, parameter sizes and results.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="new submission directory; also creates DIRECTORY.zip")
    parser.add_argument("--build-dir", default="../sydo-submission-kat-build")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--bmi2", type=int, choices=(0, 1), default=1)
    args = parser.parse_args()
    output, build = outside(args.out), outside(args.build_dir)
    archive = Path(str(output) + ".zip")
    logs = Path(str(output) + "-logs")
    if any(path.exists() for path in (output, archive, logs)):
        raise ValueError("submission directory, archive and log directory must be new")
    if build == output or output in build.parents or build in output.parents:
        raise ValueError("build and package directories must be separate")
    expected = expected_hashes()
    output.mkdir(parents=True)
    logs.mkdir()
    vectors = output / "Test_Vectors"
    vectors.mkdir()
    with serial_lock():
        subprocess.run(["sh", str(ROOT / "tests/check_ngcc.sh")], check=True)
        for impl in IMPLEMENTATIONS:
            group = "Reference_Implementation" if impl == "ref" else "Optimized_Implementation"
            for param in PARAMETERS:
                name = param + "-" + impl
                target = output / "Implementations" / group / ("sydo_" + param)
                instance(ROOT, target, param, impl)
                subprocess.run(["sh", str(target / "tests/check_ngcc.sh")], check=True,
                               stdout=subprocess.DEVNULL)
                vector = build_kat(target, param, impl, build / name, logs / name,
                                   args.cc, args.cpu, args.bmi2)
                check_vector(vector, expected)
                dest = vectors / vector.name
                if dest.exists() and dest.read_bytes() != vector.read_bytes():
                    raise ValueError("reference/optimized KAT mismatch for " + param)
                if not dest.exists():
                    copy_file(vector, dest)
                print(name + ": packaged, KAT passed", flush=True)
    shutil.copy2(ROOT / "tools/benchmark_all.sh", output / "benchmark.sh")
    (output / "benchmark.sh").chmod(0o755)
    readme = """# SYDO NGCC submission

SYDO is a post-quantum digital signature scheme based on the hardness of the syndrome decoding (SD) problem.
This package contains six parameter sets, portable C and AVX2 implementations, and KAT vectors generated with the NGCC driver.

## Build and KAT

Requires a C11 compiler, GNU Make, Python 3.8+, Linux `taskset` and `flock`.
AVX2 requires AVX2, AES-NI, PCLMULQDQ, SSSE3 and BMI2; use `BMI2=0` (scripts: `--bmi2 0`) to omit BMI2.

```sh
(cd Implementations/Reference_Implementation/sydo_160f && make -j1 CC=gcc)
(cd Implementations/Optimized_Implementation/sydo_160f && make -j1 CC=gcc)
(cd Implementations/Reference_Implementation/sydo_160f && python3 tools/kat.py --out ../kat-160f-ref)
(cd Implementations/Optimized_Implementation/sydo_160f && python3 tools/kat.py --out ../kat-160f-avx2)
```

Replace `160f` with any parameter below. Each instance provides `SIG_AlgorithmInstance.h`; KAT checks all ten records.
Test vectors are in `Test_Vectors/`.

## Benchmark

Run all twelve implementations:

```sh
./benchmark.sh --cpu 0 --rounds 200 --warmup 50 --out ../package-results
```

Or run `./benchmark/run_bench.sh --out ../instance-results` inside one instance directory.
Both commands run sequentially on one CPU: 50 warm-up calls, then the arithmetic mean of 200 measured calls.
Outputs: `benchmark.csv` (time), `metadata.txt` (measurement conditions).

Verify package files with `sha256sum -c SHA256SUMS`.

"""
    source_readme = (ROOT / "README.md").read_text()
    for heading, marker in (("Parameter sets", "## Parameter sets\n"),
                            ("Results", "### Results\n")):
        if marker in source_readme:
            section = source_readme.split(marker, 1)[1].split("\n## ", 1)[0]
            readme += "## " + heading + "\n" + section + "\n"
    (output / "README.md").write_text(readme)
    with (output / "SHA256SUMS").open("w") as hashes:
        for path in sorted(output.rglob("*")):
            if path.is_file() and path.name != "SHA256SUMS":
                value = hashlib.sha256(path.read_bytes()).hexdigest()
                hashes.write(value + "  " + path.relative_to(output).as_posix() + "\n")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as zipped:
        for path in sorted(output.rglob("*")):
            if path.is_file():
                zipped.write(path, Path(output.name) / path.relative_to(output))
    value = hashlib.sha256(archive.read_bytes()).hexdigest()
    Path(str(archive) + ".sha256").write_text(value + "  " + archive.name + "\n")
    print("Submission: " + str(archive))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
