#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"

${PROGFOLDER}/probe_cipher_provider \
--lib ${CIPHERFOLDER}/libaes_ctr_provider.so \
--confstring "keybits=128;key=0x00112233445566778899AABBCCDDEEFF;iv=0x000102030405060708090A0B0C0D0E0F" \
--plain "hello dvco running on psoc"

