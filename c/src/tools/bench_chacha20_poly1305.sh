#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

SIZE=${SIZE:-1024}
ITERS=${ITERS:-100000}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/libchacha20_poly1305_provider.so \
--confstring "" \
--size ${SIZE} \
--iters ${ITERS}

# override defaults, for example:
# SIZE=4096 ITERS=50000 ./bench_chacha20_poly1305.sh

