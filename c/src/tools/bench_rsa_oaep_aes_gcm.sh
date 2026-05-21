#!/bin/sh

PROGFOLDER="../../build/release/bin"
CIPHERFOLDER="../../build/release/lib"

# RSA-OAEP + AES-GCM envelope encryption supports normal payload sizes.
# RSA-OAEP is used only to wrap the AES-GCM content-encryption key.
SIZE=${SIZE:-4096}
ITERS=${ITERS:-1000}

${PROGFOLDER}/bench_cipher_provider \
--cipher ${CIPHERFOLDER}/librsa_oaep_aes_gcm_provider.so \
--confstring "keybits=2048" \
--size ${SIZE} \
--iters ${ITERS} \
--decrypt-mode cycle

# keybits: use 2048, 3072 or 4096
# override defaults, for example:
# SIZE=65536 ITERS=500 ./bench_rsa_oaep_aes_gcm.sh
