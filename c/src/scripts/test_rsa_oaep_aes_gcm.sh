#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"

${PROGFOLDER}/test_cipher_provider \
  --lib ${CIPHERFOLDER}/librsa_oaep_aes_gcm_provider.so \
  --confstring "keybits=2048" \
  --plain "hello dvco envelope"
