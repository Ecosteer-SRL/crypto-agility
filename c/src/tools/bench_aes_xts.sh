#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

SIZE=${SIZE:-1024}
ITERS=${ITERS:-100000}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/libaes_xts_provider.so \
--confstring "" \
--size ${SIZE} \
--iters ${ITERS}

# AES-XTS requires payloads compatible with the provider constraints.
# Use SIZE >= 16.
# override defaults, for example:
# SIZE=4096 ITERS=50000 ./bench_aes_xts.sh

