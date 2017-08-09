/*------------------------------------------------------------------------
/ OCB Version 3 Reference Code (Unoptimized C)   Last modified 12-JUN-2013
/-------------------------------------------------------------------------
/ Copyright (c) 2013 Ted Krovetz.
/
/ Permission to use, copy, modify, and/or distribute this software for any
/ purpose with or without fee is hereby granted, provided that the above
/ copyright notice and this permission notice appear in all copies.
/
/ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
/ WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
/ MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
/ ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
/ WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
/ ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
/ OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/
/ Phillip Rogaway holds patents relevant to OCB. See the following for
/ his free patent grant: http://www.cs.ucdavis.edu/~rogaway/ocb/grant.htm
/
/ Comments are welcome: Ted Krovetz <ted@krovetz.net>
/------------------------------------------------------------------------- */

/* This implementation is not optimized and is suceptible to timing attack.
/  It mirrors the OCB RFC to aid in understanding and should not be used
/  for any other purpose. This implementation manipulates data as bytes
/  rather than machine words, which avoids endian issues entirely.
/  To compile: gcc -lcrypto ocb_ref.c                                      */

#include <string.h>
#include "aes.h"

//#pragma intrinsic(memcpy, memset, memcmp)
//#define memcpy(x,y,z) __movsb(x,y,z)
//#define memset(x,y,z) __stosb(x,y,z)

#define RotWord(x) ROTR32(x, 8)

uint32_t gf_mul2 (uint32_t w) {
  uint32_t t = w & 0x80808080;
  
  return ( (w ^ t ) << 1) ^ ( ( t >> 7) * 0x0000001B);
}

// ------------------------------------
// multiplicative inverse
// ------------------------------------
uint8_t gf_mulinv (uint8_t x)
{
  uint8_t y=x, i;

  if (x)
  {
    // calculate logarithm gen 3
    for (y=1, i=0; ;i++) {
      y ^= gf_mul2 (y);
      if (y==x) break;
    }
    i+=2;
    // calculate anti-logarithm gen 3
    for (y=1; i; i++) {
      y ^= gf_mul2(y);
    }
  }
  return y;
}
// ------------------------------------
// substitute byte
// ------------------------------------
uint8_t SubByte (uint8_t x, int enc)
{
  uint8_t i, y=0, sb;

  if (enc==AES_ENCRYPT)
  {
    sb = y = gf_mulinv (x);

    for (i=0; i<4; i++) {
      y   = ROTL8(y, 1);
      sb ^= y;
    }
    sb ^= 0x63;
  } else {
    // ------------------
    y   = x ^ 0x63;
    y   = ROTL8(y, 1);
    sb  = y;
    y   = ROTL8(y, 2);
    sb ^= y;
    y   = ROTL8(y, 3);
    sb ^= y;
    sb  = gf_mulinv(sb);
  }
  return sb;
}
// ------------------------------------
// substitute 4 bytes
// ------------------------------------
uint32_t SubWord (uint32_t x)
{
  uint8_t i;
  uint32_t r=0;

  for (i=0; i<4; i++) {
    r |= SubByte(x & 0xFF, AES_ENCRYPT);
    r  = ROTR32(r, 8);
    x >>= 8;
  }
  return r;
}
// ------------------------------------
// substitute 16 bytes
// ------------------------------------
void SubBytes (aes_blk *state, int enc)
{
  int8_t i;

  for (i=0; i<16; i++) {
    state->v8[i] = SubByte(state->v8[i], enc);
  }
}
// ------------------------------------
// shift rows in state
// ------------------------------------
void ShiftRows (aes_blk *state, int enc)
{
  uint32_t x, i, j;

  // shift 4 rows
  for (i=0; i<4; i++) {
    x=0;
    // get row
    for (j=i; j<16; j+=4) {
      x |= state->v8[j];
      x=ROTR32(x, 8);
    }
    // rotate depending on enc
    if (enc==AES_ENCRYPT) {
      x = ROTR32(x, i*8);
    } else {
      x = ROTL32(x, i*8);
    }
    // set row
    for (j=i; j<16; j+=4) {
      state->v8[j] = (x & 0xff);
      x >>= 8;
    }
  }
}

// ------------------------------------
// mix columns in state
// ------------------------------------
uint32_t MixColumn (uint32_t w) {
  return ROTR32(w, 8) ^ 
         ROTR32(w, 16) ^ 
         ROTR32(w, 24) ^ 
         gf_mul2(ROTR32(w, 8) ^ w);
}

void MixColumns (aes_blk *state, int enc)
{
  uint32_t i, t, w;

  for (i=0; i<4; i++)
  {
    w = state->v32[i];
    if (enc==AES_DECRYPT) {
      t = ROTR32(w, 16) ^ w;
      t = gf_mul2(gf_mul2(t));
      w ^= t;
    }
    state->v32[i] = MixColumn(w);
  }
}
// ------------------------------------
// add 16 bytes of key to state
// ------------------------------------
void AddRoundKey (aes_blk *state, uint32_t w[], int rnd)
{
  uint32_t i;
  uint8_t *key=(uint8_t*)&w[rnd*4];

  for (i=0; i<16; i++) {
    state->v8[i] ^= key[i];
  }
}
// ------------------------------------
// create AES-256 key
// ------------------------------------
void AES_setkey (void *key, aes_ctx *ctx)
{
  int i;
  uint32_t x;
  uint32_t *w=(uint32_t*)ctx->w;
  uint8_t rcon=1;

  memcpy ((uint8_t*)&ctx->w[0], key, Nk*4);

  for (i=Nk; i<Nb*(Nr+1); i++)
  {
    x=w[i-1];
    if ((i % Nk)==0) {
      x = RotWord(x);
      x = SubWord(x) ^ rcon;
      rcon=gf_mul2(rcon);
    } else if (Nk > 6 && i % Nk == 4) {
      x=SubWord(x);
    }
    w[i] = w[i-Nk] ^ x;
  }
}
// ------------------------------------
// encrypt/decrypt 16 bytes of state
// ------------------------------------
void AES_encrypt (void *in, void *out, aes_ctx *ctx, int enc)
{
  uint8_t round;
  uint32_t *w=(uint32_t*)ctx->w;
  aes_blk state;
  
  memcpy (state.v8, in, 16);

  if (enc==AES_ENCRYPT)
  {
    AddRoundKey (&state, w, 0);

    for (round=1; round<Nr; round++)
    {
      SubBytes (&state, enc);
      ShiftRows (&state, enc);
      MixColumns (&state, enc);
      AddRoundKey (&state, w, round);
    }
  }
  else
  {
    AddRoundKey (&state, w, Nr);

    for (round=Nr-1; round>0; round--)
    {
      SubBytes (&state, enc);
      ShiftRows (&state, enc);
      AddRoundKey (&state, w, round);
      MixColumns (&state, enc);
    }
  }
  
  SubBytes (&state, enc);
  ShiftRows (&state, enc);
  AddRoundKey (&state, w, round);
  
  memcpy (out, state.v8, 16);
}

#define CAESAR 0      /* Set non-zero for submission to CAESAR competition */

#if CAESAR
#include "api.h"
#include "crypto_aead.h"
#define KEYBYTES   CRYPTO_KEYBYTES
#define NONCEBYTES CRYPTO_NPUBBYTES
#define TAGBYTES   CRYPTO_ABYTES
#else
#define KEYBYTES   (256/8)
#define NONCEBYTES (96/8)
#define TAGBYTES   (64/8)
#endif

#if !(KEYBYTES==16 || KEYBYTES==24 || KEYBYTES==32) ||  \
     (NONCEBYTES > 15 || NONCEBYTES < 0) ||             \
     (TAGBYTES > 16 || TAGBYTES < 1)
#error -- KEYBYTES, NONCEBYTES, or TAGBYTES is an illegal value
#endif

typedef unsigned char block[16];

/* ------------------------------------------------------------------------- */

static void xor_block(block d, block s1, block s2) {
    unsigned i;
    for (i=0; i<16; i++)
        d[i] = s1[i] ^ s2[i];
}

/* ------------------------------------------------------------------------- */

static void double_block(block d, block s) {
    unsigned i;
    unsigned char tmp = s[0];
    for (i=0; i<15; i++)
        d[i] = (s[i] << 1) | (s[i+1] >> 7);
    d[15] = (s[15] << 1) ^ ((tmp >> 7) * 135);
}

/* ------------------------------------------------------------------------- */

static void calc_L_i(block l, block ldollar, unsigned i) {
    double_block(l, ldollar);         /* l is now L_0               */
    
    for ( ; (i & 1) == 0 ; i >>= 1)
        double_block(l,l);            /* double for each trailing 0 */
}

/* ------------------------------------------------------------------------- */

static void hash(block result, unsigned char *k,
                 unsigned char *a, unsigned abytes) {
    aes_ctx aes_key;
    block lstar, ldollar, offset, sum, tmp;
    unsigned i;
    
    /* Key-dependent variables */
    
    /* L_* = ENCIPHER(K, zeros(128)) */
    AES_setkey(k, &aes_key);
    memset(tmp, 0, 16);
    AES_encrypt(tmp, lstar, &aes_key, AES_ENCRYPT);
    /* L_$ = double(L_*) */
    double_block(ldollar, lstar); 
    
    /* Process any whole blocks */
    
    /* Sum_0 = zeros(128) */
    memset(sum, 0, 16);
    /* Offset_0 = zeros(128) */
    memset(offset, 0, 16);
    for (i=1; i<=abytes/16; i++, a = a + 16) {
        /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
        calc_L_i(tmp, ldollar, i);
        xor_block(offset, offset, tmp);
        /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i) */
        xor_block(tmp, offset, a);
        AES_encrypt(tmp, tmp, &aes_key, AES_ENCRYPT);
        xor_block(sum, sum, tmp);
    }

    /* Process any final partial block; compute final hash value */

    abytes = abytes % 16;  /* Bytes in final block */
    if (abytes > 0) {
        /* Offset_* = Offset_m xor L_* */
        xor_block(offset, offset, lstar);
        /* tmp = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_* */
        memset(tmp, 0, 16);
        memcpy(tmp, a, abytes);
        tmp[abytes] = 0x80;
        xor_block(tmp, offset, tmp);
        /* Sum = Sum_m xor ENCIPHER(K, tmp) */
        AES_encrypt(tmp, tmp, &aes_key, AES_ENCRYPT);
        xor_block(sum, tmp, sum);
    }
    
    memcpy(result, sum, 16);
}

/* ------------------------------------------------------------------------- */

static int ocb_crypt(unsigned char *out, unsigned char *k, unsigned char *n,
                     unsigned char *a, unsigned abytes,
                     unsigned char *in, unsigned inbytes, int encrypting) {
    aes_ctx aes_encrypt_key, aes_decrypt_key;
    block lstar, ldollar, sum, offset, ktop, pad, nonce, tag, tmp;
    unsigned char stretch[24];
    unsigned bottom, byteshift, bitshift, i;
    
    /* Setup AES and strip ciphertext of its tag */
    if ( ! encrypting ) {
         if (inbytes < TAGBYTES) return -1;
         inbytes -= TAGBYTES;
         AES_setkey(k, &aes_decrypt_key);
    }
    AES_setkey(k, &aes_encrypt_key);
     
    /* Key-dependent variables */

    /* L_* = ENCIPHER(K, zeros(128)) */
    memset(tmp, 0, 16);
    AES_encrypt(tmp, lstar, &aes_encrypt_key, AES_ENCRYPT);
    
    /* L_$ = double(L_*) */
    double_block(ldollar, lstar); 

    /* Nonce-dependent and per-encryption variables */

    /* Nonce = zeros(127-bitlen(N)) || 1 || N */
    memset(nonce,0,16);
    memcpy(&nonce[16-NONCEBYTES],n,NONCEBYTES);
    
    nonce[0] = (unsigned char)(((TAGBYTES * 8) % 128) << 1);
    nonce[16-NONCEBYTES-1] |= 0x01;
    
    /* bottom = str2num(Nonce[123..128]) */
    bottom = nonce[15] & 0x3F;
    
    /* Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6)) */
    nonce[15] &= 0xC0;
    
    AES_encrypt(nonce, ktop, &aes_encrypt_key, AES_ENCRYPT);
    
    /* Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]) */
    memcpy(stretch, ktop, 16);
    memcpy(tmp, &ktop[1], 8);
    
    xor_block(tmp, tmp, ktop);
    
    memcpy(&stretch[16],tmp,8);
    
    /* Offset_0 = Stretch[1+bottom..128+bottom] */
    byteshift = bottom>>3;
    bitshift  = bottom&7;
    
    if (bitshift != 0)
        for (i=0; i<16; i++)
            offset[i] = (stretch[i+byteshift] << bitshift) |
                        (stretch[i+byteshift+1] >> (8-bitshift));
    else
        for (i=0; i<16; i++)
            offset[i] = stretch[i+byteshift];
          
    /* Checksum_0 = zeros(128) */
    memset(sum, 0, 16);

    /* Process any whole blocks */
    for (i=1; i<=inbytes/16; i++, in=in+16, out=out+16) {
      
        /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
        calc_L_i(tmp, ldollar, i);
        
        xor_block(offset, offset, tmp);
        xor_block(tmp, offset, in);
        
        if (encrypting) {
            /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
            AES_encrypt(tmp, tmp, &aes_encrypt_key, AES_ENCRYPT);
            
            xor_block(out, offset, tmp);
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, in, sum);
        } else {
            /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
            AES_encrypt(tmp, tmp, &aes_decrypt_key, AES_DECRYPT);
            
            xor_block(out, offset, tmp);
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, out, sum);
        }
    }

    /* Process any final partial block and compute raw tag */
    inbytes = inbytes & 15;  /* Bytes in final block */
    
    if (inbytes > 0) {
        /* Offset_* = Offset_m xor L_* */
        xor_block(offset, offset, lstar);
        /* Pad = ENCIPHER(K, Offset_*) */
        AES_encrypt(offset, pad, &aes_encrypt_key, AES_ENCRYPT);
        
        if (encrypting) {
            /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
            memset(tmp, 0, 16);
            memcpy(tmp, in, inbytes);
            
            tmp[inbytes] = 0x80;
            
            xor_block(sum, tmp, sum);
            
            /* C_* = P_* xor Pad[1..bitlen(P_*)] */
            xor_block(pad, tmp, pad);
            memcpy(out, pad, inbytes);
            out = out + inbytes;
        } else {
            /* P_* = C_* xor Pad[1..bitlen(C_*)] */
            memcpy(tmp, pad, 16);
            memcpy(tmp, in, inbytes);
            
            xor_block(tmp, pad, tmp);
            
            tmp[inbytes] = 0x80;     /* tmp == P_* || 1 || zeros(127-bitlen(P_*)) */
            memcpy(out, tmp, inbytes);
            /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
            xor_block(sum, tmp, sum);
            in = in + inbytes;
        }
    }
    
    /* Tag = ENCIPHER(K, Checksum xor Offset xor L_$) xor HASH(K,A) */
    xor_block(tmp, sum, offset);
    xor_block(tmp, tmp, ldollar);
    
    AES_encrypt(tmp, tag, &aes_encrypt_key, AES_ENCRYPT);
    
    hash(tmp, k, a, abytes);
    xor_block(tag, tmp, tag);
    
    if (encrypting) {
        memcpy(out, tag, TAGBYTES);
        return 0;
    } else
        return (memcmp(in,tag,TAGBYTES) ? -1 : 0);     /* Check for validity */
}

/* ------------------------------------------------------------------------- */

#define OCB_ENCRYPT 1
#define OCB_DECRYPT 0

void ocb_encrypt(unsigned char *c, unsigned char *k, unsigned char *n,
                 unsigned char *a, unsigned abytes,
                 unsigned char *p, unsigned pbytes) {
    ocb_crypt(c, k, n, a, abytes, p, pbytes, OCB_ENCRYPT);
}

/* ------------------------------------------------------------------------- */

int ocb_decrypt(unsigned char *p, unsigned char *k, unsigned char *n,
                unsigned char *a, unsigned abytes,
                unsigned char *c, unsigned cbytes) {
    return ocb_crypt(p, k, n, a, abytes, c, cbytes, OCB_DECRYPT);
}

/* -------------------------------------------------------------------------

#if CAESAR

int crypto_aead_encrypt(
unsigned char *c,unsigned long long *clen,
const unsigned char *m,unsigned long long mlen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k
)
{
    *clen = mlen + TAGBYTES;
    ocb_crypt(c, k, npub, ad, adlen, m, mlen, OCB_ENCRYPT);
    return 0;
}

int crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
    *mlen = clen - TAGBYTES;
    return ocb_crypt(m, k, npub, ad, adlen, c, clen, OCB_DECRYPT);
}

#else   // Test against RFC's vectors

#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned char zeroes[128] = {0,};
    unsigned char nonce[12] = {0,};
    unsigned char p[128] = {0,};
    unsigned char final[16];
    unsigned char *c;
    unsigned i, next;
    int result;
    
    // Encrypt and output RFC vector
    c = malloc(22400);
    next = 0;
    for (i=0; i<128; i++) {
        nonce[11] = i;
        ocb_encrypt(c+next, zeroes, nonce, zeroes, i, zeroes, i);
        next = next + i + TAGBYTES;
        ocb_encrypt(c+next, zeroes, nonce, zeroes, 0, zeroes, i);
        next = next + i + TAGBYTES;
        ocb_encrypt(c+next, zeroes, nonce, zeroes, i, zeroes, 0);
        next = next + TAGBYTES;
    }
    nonce[11] = 0;
    ocb_encrypt(final, zeroes, nonce, c, next, zeroes, 0);
    if (NONCEBYTES == 12) {
        printf("AEAD_AES_%d_OCB_TAGLEN%d Output: ", KEYBYTES*8, TAGBYTES*8);
        for (i=0; i<TAGBYTES; i++) printf("%02X", final[i]); printf("\n");
    }
    
    // Decrypt and test for all zeros and authenticity
    result = ocb_decrypt(p, zeroes, nonce, c, next, final, TAGBYTES);
    if (result) { printf("FAIL\n"); return 0; }
    next = 0;
    for (i=0; i<128; i++) {
        nonce[11] = i;
        result = ocb_decrypt(p, zeroes, nonce, zeroes, i, c+next, i+TAGBYTES);
        if (result || memcmp(p,zeroes,i)) { printf("FAIL\n"); return 0; }
        next = next + i + TAGBYTES;
        result = ocb_decrypt(p, zeroes, nonce, zeroes, 0, c+next, i+TAGBYTES);
        if (result || memcmp(p,zeroes,i)) { printf("FAIL\n"); return 0; }
        next = next + i + TAGBYTES;
        result = ocb_decrypt(p, zeroes, nonce, zeroes, i, c+next, TAGBYTES);
        if (result || memcmp(p,zeroes,i)) { printf("FAIL\n"); return 0; }
        next = next + TAGBYTES;
    }
    return 0;
}

#endif*/
