#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

SIZE=${SIZE:-10240}
ITERS=${ITERS:-100000}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/libascon_aead128_provider.so \
--confstring "" \
--size ${SIZE} \
--iters ${ITERS} \
--decrypt-mode cycle \
--aad "aadamello"

#--decrypt-mode reuse

