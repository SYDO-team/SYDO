#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
sha256sum -c <<'DIGESTS'
27446371eccf14383e5a333dfed6333ed9a2232580d0a52c1c681bc2074a8368  third_party/ngcc/auxfunc.c
39986e91d9af503eafb568b0c18e50eb9ab5fceca140ddd26924343a09284e74  third_party/ngcc/auxfunc.h
0df0ac78c828bd43bf05724398fa530767d753aa7801a1d1fa5d621321ec797e  third_party/ngcc/drng.c
d758aa7f5618bb781960fb7193b536897a09b1fdd7acca5ad8a45495d0e147a7  third_party/ngcc/drng.h
2403e000378a375e12c57350aa8a09bba580e3bcd4ee31fdda1944929cf61dfd  third_party/ngcc/KAT_SIG.c
240367c4d5008a14cb3715df92568c49052e8140935a8f7af44ad35f7529fe8c  api/ngcc/160f/SIG_AlgorithmInstance.h
adb2918aa4a63ecdbb12d5c1e24ca6199fd928877be1aaee110509e1d114162e  api/ngcc/160s/SIG_AlgorithmInstance.h
c4173af5de8c67dc205b57e01a4b06e07fc147bea04e64efc23556f84298dec5  api/ngcc/256f/SIG_AlgorithmInstance.h
35ce712a253611313d5840234dce9853d4d77ecc1d703df86d695b7c927236a9  api/ngcc/256s/SIG_AlgorithmInstance.h
32eccf61eb9e83edc6eeca9d717817f10db8aaab90cac99cdbd5d151d676ae4e  api/ngcc/512f/SIG_AlgorithmInstance.h
c4c0b1fc1f45c78d13222b0e530da6662935df15d5dd608998d9fd1ebfc34e06  api/ngcc/512s/SIG_AlgorithmInstance.h
DIGESTS
