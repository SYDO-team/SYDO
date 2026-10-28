#!/usr/bin/env python3
"""Build the official KAT driver and check its complete output."""

import argparse
import contextlib
import hashlib
import os
from pathlib import Path
import subprocess
import sys


PARAMETERS = ("160f", "160s", "256f", "256s", "512f", "512s")
IMPLEMENTATIONS = ("ref", "avx2")
ROOT = Path(__file__).resolve().parent.parent


def outside(path, source=ROOT):
    path = Path(path).expanduser().resolve()
    if path == source or source in path.parents:
        raise ValueError("output and build directories must be outside the source directory")
    return path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def expected_hashes(source=ROOT):
    return dict((name, value) for value, name in
                (line.split() for line in (source / "tests/kat.sha256").read_text().splitlines()))


def check_vector(path, expected):
    if digest(path) != expected[path.name]:
        raise ValueError("KAT mismatch: " + str(path))


@contextlib.contextmanager
def serial_lock():
    import fcntl
    lock = Path("/tmp") / ("sydo-benchmark-%d.lock" % os.getuid())
    with lock.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def build_kat(source, param, impl, build, output, cc, cpu, bmi2):
    build.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    with (output / "build.log").open("w") as log:
        subprocess.run(["taskset", "-c", str(cpu), "make", "-C", str(source), "-j1", "-B",
                        "CC=" + cc, "PARAM=" + param, "IMPL=" + impl, "BMI2=" + str(bmi2),
                        "PROFILE=0", "BUILD_DIR=" + str(build), "kat"],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    with (output / "kat.log").open("w") as log:
        subprocess.run(["taskset", "-c", str(cpu), str(build / "kat_sig")], cwd=output,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    return output / "output" / ("KAT_SIG_sydo_" + param + ".txt")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--param", choices=("all",) + PARAMETERS, default="all")
    parser.add_argument("--impl", choices=("both",) + IMPLEMENTATIONS, default="both")
    parser.add_argument("--out", required=True, help="KAT and log directory")
    parser.add_argument("--build-dir", default="../sydo-kat-build")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--bmi2", type=int, choices=(0, 1), default=1)
    args = parser.parse_args()
    output, build = outside(args.out), outside(args.build_dir)
    expected = expected_hashes()
    params = PARAMETERS if args.param == "all" else (args.param,)
    impls = IMPLEMENTATIONS if args.impl == "both" else (args.impl,)
    with serial_lock():
        for param in params:
            for impl in impls:
                name = param + "-" + impl
                vector = build_kat(ROOT, param, impl, build / name, output / name,
                                   args.cc, args.cpu, args.bmi2)
                check_vector(vector, expected)
                print(name + ": KAT passed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
