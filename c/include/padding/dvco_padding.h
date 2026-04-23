// ver:  1.0
// auth: graz
// date: 12/11/2025


#ifndef DOP_PADDING_H
#define DOP_PADDING_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>


#ifndef NEW_REL
#define NEW_REL
#endif

#ifdef __cplusplus
    extern "C" {
#endif

int dvco_pkcs7_pad
(
    const uint8_t *in       //  [in]    cleartext to be padded
,   size_t in_len           //  [in]    len of the cleartext (in bytes) 
,   uint8_t *out            //  [out]   padded cleartext
,   size_t *out_len_inout   //  [out]   len of the padded cleartext
,   size_t block_size       //  [in]    block size to be used for the padding
);

// returns 0 on success, non-zero on error
int dvco_pkcs7_unpad
(
    uint8_t *buf            //  [in/out]    padded cleartext/unpadded cleartext
,   size_t *len_inout       //  [in/out]    len of padded cleartext/len of unpadded cleartext
,   size_t block_size       //  [in]        block size to be used for unpadding
);

#ifdef __cplusplus
    }
#endif


#endif /* DOP_PADDING_H */
