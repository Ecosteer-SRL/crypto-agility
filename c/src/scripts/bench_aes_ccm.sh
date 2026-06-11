#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

SIZE=${SIZE:-1024}
ITERS=${ITERS:-100000}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/libaes_ccm_provider.so \
--confstring "" \
--size ${SIZE} \
--iters ${ITERS} \
--decrypt-mode cycle

# override defaults, for example:
# SIZE=4096 ITERS=50000 ./bench_aes_ccm.sh

