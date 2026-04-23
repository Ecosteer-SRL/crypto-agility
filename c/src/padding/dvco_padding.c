// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.0

#include <padding/dvco_padding.h>


#include <stddef.h>
#include <stdint.h>
#include <string.h>


#define DVCO_PAD_OK              0
#define DVCO_PAD_ERRINVALIDARG   1
#define DVCO_PAD_ERRBUFTOOSMALL  2
#define DVCO_PAD_INVALID         3

/*
  Return codes:
    0   success
   -1   invalid argument
   -2   output buffer too small
   -3   invalid padding (unpad)
*/

int dvco_pkcs7_pad
(
   const uint8_t *in       // cleartext to be padded
,  size_t inLen            // len of the cleartext to be padded
,  uint8_t *out            // padded cleartext
,  size_t *outLenInOut     // len of the padded cleartext
,  size_t blockSize        // len in bytes of the block size
)
{
   // in, out and outLenInOut must be valid pointers (not NULL)
   if (!in || !out || !outLenInOut) return DVCO_PAD_ERRINVALIDARG;
   // block size must be different than 0 and less than 255
   if (blockSize == 0 || blockSize > 255) return DVCO_PAD_ERRINVALIDARG;

   size_t cap = *outLenInOut;

   // PKCS7: always add padding, even if already aligned
   size_t pad = blockSize - (inLen % blockSize);
   if (pad == 0) pad = blockSize;

   if (cap < (inLen + pad)) return DVCO_PAD_ERRBUFTOOSMALL;

   //   copy the cleartext to the buffer holding the padded cleartext
   if (inLen > 0) memcpy(out, in, inLen);
   //   set the padding into the padded cleartext
   memset((out + inLen), (uint8_t)pad, pad);

   *outLenInOut = inLen + pad;
   return DVCO_PAD_OK;
}

// Unpads PKCS7 in place.
// `buf` IN/OUT: plaintext including padding on input; unchanged bytes on output
// `*lenInOut` IN: total length; OUT: unpadded length
int dvco_pkcs7_unpad
(
   uint8_t *buf         // [in/out] padded cleartext
,  size_t *lenInOut     // [in/out] len of the padded cleartext/len of the unpadded cleartext
,  size_t blockSize     // block size to be used for unpadding
)
{
   // buf and lenInOut must be valid
   if (!buf || !lenInOut) return DVCO_PAD_ERRINVALIDARG;
   // clock size cannot be 0 and must be less than 255
   if (blockSize == 0 || blockSize > 255) return DVCO_PAD_ERRINVALIDARG;

   size_t len = *lenInOut;
   if (len == 0) return DVCO_PAD_INVALID;

   // Optional strictness: PKCS7 padded plaintext length should be multiple of blockSize
   if ((len % blockSize) != 0) return DVCO_PAD_INVALID;

   // get the last byte in the padded cleartext to check the padding len
   uint8_t pad = buf[len - 1];
   if (pad == 0 || pad > blockSize) return DVCO_PAD_INVALID;
   if ((size_t)pad > len) return DVCO_PAD_INVALID;

   // Verify all padding bytes match pad value
   for (size_t i = 0; i < (size_t)pad; i++) {
      if (buf[len - 1 - i] != pad) return DVCO_PAD_INVALID;
   }

   len -= (size_t)pad;
   *lenInOut = len;

   // If you want a C-string terminator for string payloads, do it outside:
   // buf[len] = '\0';  // only if buf has room and plaintext is textual

   return DVCO_PAD_OK;
}
