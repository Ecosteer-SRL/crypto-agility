#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

${PROGFOLDER}/bench_cipher_provider \
--lib ${CIPHERFOLDER}/libaes_ccm_provider.so \
--confstring "keybits=128" \
--size 1024 \
--iters 100000 \
--aad "aadamello" \
--decrypt-mode cycle

