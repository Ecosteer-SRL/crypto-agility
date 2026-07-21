#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

SIZE=${SIZE:-1048576}
ITERS=${ITERS:-5000}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/libaes_gcm_provider.so \
--confstring "" \
--size ${SIZE} \
--iters ${ITERS} \
--decrypt-mode cycle \
--aad "aadamello"



