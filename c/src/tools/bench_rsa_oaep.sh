#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

# RSA-OAEP with 2048-bit key and SHA-256 can encrypt only small payloads.
# Keep SIZE <= 190 for keybits=2048.
SIZE=${SIZE:-64}
ITERS=${ITERS:-100}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/librsa_oaep_provider.so \
--confstring "keybits=2048" \
--size ${SIZE} \
--iters ${ITERS} \
--decrypt-mode cycle

# keybits: use 2048, 3072 or 4096
# override defaults, for example:
# SIZE=128 ITERS=5000 ./bench_rsa_oaep.sh
