#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

SIZE=${SIZE:-1024}
ITERS=${ITERS:-200000}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/libaes_cbc_provider.so \
--confstring "keybits=256" \
--size ${SIZE} \
--iters ${ITERS}

# keybits: use 128, 192 or 256
# override defaults, for example:
# SIZE=4096 ITERS=50000 ./bench_test_aes_cbc.sh

