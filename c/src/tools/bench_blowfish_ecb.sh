#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

SIZE=${SIZE:-1024}
ITERS=${ITERS:-100000}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/libblowfish_ecb_provider.so \
--confstring "" \
--size ${SIZE} \
--iters ${ITERS}

# override defaults, for example:
# SIZE=4096 ITERS=50000 ./bench_blowfish_ecb.sh

