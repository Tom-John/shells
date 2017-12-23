/**
  Copyright © 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#include "crypto.h"

#ifdef TEST
void bin2hex(
    char *s, 
    uint8_t *buf, 
    uint32_t len)
{
  int i;
  printf("\n%s = ", s);
  for (i=0; i<len; i++) {
    printf ("%02x", buf[i]);
  }
}
#endif

void speck64_encrypt(
    const void *key,
    void *in)
{
    uint32_t i, t, k0, k1, k2, k3, x0, x1;
    w64_t   *x=(w64_t*)in;
    w128_t  *k=(w128_t*)key;
    
    // copy 128-bit key to local registers
    k0 = k->w[0]; k1 = k->w[1];
    k2 = k->w[2]; k3 = k->w[3];    

    // copy M to local space
    x0 = x->w[0]; x1 = x->w[1];

    for (i=0; i<27; i++) {
      // encrypt block
      x0 = (ROTR32(x0, 8) + x1) ^ k0;
      x1 =  ROTL32(x1, 3) ^ x0;
      
      // create next subkey
      k1 = (ROTR32(k1, 8) + k0) ^ i;
      k0 =  ROTL32(k0, 3) ^ k1;
      
      XCHG(k3, k2, t);
      XCHG(k3, k1, t);    
    }
    // save result
    x->w[0] = x0; x->w[1] = x1;
}

#define ENCRYPT_BLK(x, y) speck64_encrypt(x, y)
#define GET_MAC(w, x, y, z) lightmac_tag(w, x, y, z)

void lightmac_tag(
    crypto_ctx *c, 
    void *msg, 
    uint32_t msglen, 
    void *tag) 
{
    uint8_t  *data=(uint8_t*)msg;
    uint8_t  *key=(uint8_t*)c->m_key;
    uint32_t idx, ctr, i;
    bc_blk   m;
    bc_blk   *t=(bc_blk*)tag;
    
    // zero initialize T
    t->w[0] = 0; t->w[1] = 0;

    // set counter + index to zero
    ctr = 0; idx = 0;
    
    // while we have msg data
    while (msglen) {
      // add byte to M
      m.b[COUNTER_LENGTH + idx++] = *data++;
      // M filled?
      if (idx == (BLOCK_LENGTH - COUNTER_LENGTH)) {
        // add S counter in big endian format
        ctr++;
        m.ctr = SWAP32(ctr);
        // encrypt M with E using K1
        ENCRYPT_BLK(key, &m);
        // update T
        t->w[0] ^= m.w[0];
        t->w[1] ^= m.w[1];
        // reset index      
        idx = 0;
      }
      // decrease length
      msglen--;
    }
    // add the end bit
    m.b[COUNTER_LENGTH + idx++] = 0x80;  
    // update T with anything remaining
    for (i=0; i<idx; i++) {
      t->b[i] ^= m.b[COUNTER_LENGTH + i];
    }
    // advance key to K2
    key += BC_KEY_LENGTH;
    // encrypt T with E using K2
    ENCRYPT_BLK(key, t);
}

// update the encryption counter
void update_ctr (crypto_ctx *ctx)
{
    int i;
    
    for (i=BLOCK_LENGTH-1; i>=0; i--) {
      ctx->e_ctr[i]++;
      if (ctx->e_ctr[i]) {
        break;
      }
    }
}

// encrypt or decrypt a stream of bytes
// expects buf to have enough capacity for MAC
// returns -1 for error else length of plaintext/ciphertext
int encrypt(
    crypto_ctx *ctx, 
    void *buf, 
    uint32_t buflen, 
    int enc)
{
    uint32_t   r, i, len;
    uint8_t    mac[TAG_LENGTH];
    uint8_t    strm[BLOCK_LENGTH]; 

    uint8_t    *msg   = (uint8_t*)buf;
    uint32_t   msglen = buflen;
    
    // decrypting?
    if (enc == CRYPT_DECRYPT) {
      // subtract MAC length
      msglen -= TAG_LENGTH;
      // generate MAC of ciphertext
      GET_MAC(ctx, msg, msglen, mac);
      // compare with what we received
      // if not equal, return error
      if (memcmp(mac, &msg[msglen], TAG_LENGTH)) {
        return -1;  // invalid mac
      }
    }
    
    len = msglen;
    
    // encrypt or decrypt bytes
    while (len) {      
      // copy counter to local buffer
      memcpy (strm, ctx->e_ctr, BLOCK_LENGTH);
      // encrypt counter
      ENCRYPT_BLK(ctx->e_key, strm);
      // xor 1 block or whatever remaining
      r = MIN(len, BLOCK_LENGTH);
      // xor message with ciphertext stream
      for (i=0; i<r; i++) {
        msg[i] ^= strm[i];
      }      
      // update counter
      update_ctr(ctx);
      // update length + message pointer
      len -= r;
      msg += r;
    }
    
    // encrypting? add MAC of ciphertext
    if (enc == CRYPT_ENCRYPT) {
      GET_MAC(ctx, buf, buflen, msg);
      // update total length of message being sent
      msglen += TAG_LENGTH;
    }    
    return msglen;
}

#ifdef TEST

int main(int argc, char *argv[])
{
    uint8_t    buf[BLOCK_LENGTH+TAG_LENGTH]={1,2,3,4,5,6,7,8};
    uint8_t    tag[TAG_LENGTH];
    uint8_t    e_key[BC_KEY_LENGTH]={16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
    uint8_t    m_key[BC_KEY_LENGTH*2]=
         {17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
          32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47};
    int        ret, len, e_equ, m_equ;
    crypto_ctx ctx;
    uint8_t result[BLOCK_LENGTH+TAG_LENGTH]=
        {0xdc,0x91,0xb6,0xb8,0x24,0xf7,0xa4,0x00,0x5a,0x31,0x5f,0xf8,0x02,0xb7,0x87,0x4c};
    
    memset(&ctx,0, sizeof(ctx));
    memcpy(ctx.e_key, e_key, BC_KEY_LENGTH);
    memcpy(ctx.m_key, m_key, BC_KEY_LENGTH*2);

    bin2hex("plaintext", buf, BLOCK_LENGTH);
    bin2hex("bc key",    ctx.e_key, BC_KEY_LENGTH);
    bin2hex("mac key",   ctx.m_key, BC_KEY_LENGTH*2);
    bin2hex("expected result",    result, BLOCK_LENGTH+TAG_LENGTH);
    
    len=encrypt(&ctx, buf, 
        BLOCK_LENGTH, CRYPT_ENCRYPT);
    
    //lightmac_tag(&ctx, buf, BLOCK_LENGTH, tag);
    //bin2hex("tag", tag, TAG_LENGTH);
    
    e_equ=(memcmp(buf, result, BLOCK_LENGTH)==0);
    m_equ=(memcmp(&buf[BLOCK_LENGTH], &result[BLOCK_LENGTH], BLOCK_LENGTH)==0);
    
    printf ("\nEncryption : %s", 
        e_equ ? "OK" : "FAILED");

    printf ("\nMAC : %s", 
        m_equ ? "OK" : "FAILED");
        
    bin2hex("ciphertext", buf, len);
    
    printf ("\nEncrypted length = %i", len);
    
    memset(&ctx,0, sizeof(ctx));
    memcpy(ctx.e_key, e_key, BC_KEY_LENGTH);
    memcpy(ctx.m_key, m_key, BC_KEY_LENGTH*2);
    
    ret=encrypt(&ctx, buf, len, CRYPT_DECRYPT);
    
    if (ret>0) bin2hex("plaintext", buf, ret);
    
    printf ("\nDecryption : %s", 
        ret<=0 ? "FAILED" : "OK");
    return 0;
}
#endif

