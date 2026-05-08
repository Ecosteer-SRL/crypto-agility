#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

SIZE=${SIZE:-1024}
ITERS=${ITERS:-100000}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/libaes_ctr_provider.so \
--confstring "keybits=256" \
--size ${SIZE} \
--iters ${ITERS} \
--decrypt-mode cycle

# keybits: use 128, 192 or 256
# override defaults, for example:
# SIZE=4096 ITERS=50000 ./bench_aes_ctr.sh

