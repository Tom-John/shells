/**
  Copyright © 2016 Odzhan. All Rights Reserved.

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

#include "spp.h"

/**F*********************************************
 *
 * entrypoint of PIC
 *
 ************************************************/
BIGNUM *BN_lebin2bn(const uint8_t *s, int len, BIGNUM *ret)
{
  unsigned int i, m;
  unsigned int n;
  BN_ULONG l;
  BIGNUM *bn = NULL;

  if (ret == NULL)
      ret = bn = BN_new();
  if (ret == NULL)
      return (NULL);
  bn_check_top(ret);
  s += len - 1;
  /* Skip trailing zeroes. */
  for ( ; len > 0 && *s == 0; s--, len--)
      continue;
  n = len;
  if (n == 0) {
      ret->top = 0;
      return ret;
  }
  i = ((n - 1) / BN_BYTES) + 1;
  m = ((n - 1) % (BN_BYTES));
  if (bn_wexpand(ret, (int)i) == NULL) {
      BN_free(bn);
      return NULL;
  }
  ret->top = i;
  ret->neg = 0;
  l = 0;
  while (n--) {
      l = (l << 8L) | *(s--);
      if (m-- == 0) {
          ret->d[--i] = l;
          l = 0;
          m = BN_BYTES - 1;
      }
  }
  /*
   * need to call this due to clear byte at top if avoiding having the top
   * bit set (-ve number)
   */
  bn_correct_top(ret);
  return ret;
}

/**F*********************************************
 *
 * display keys, only for debugging
 *
 ************************************************/
void spp_dump(void *tek, int len, char *str) {
#if defined(DEBUG) && DEBUG > 0
  int i;
  printf ("\n%s = ", str);
  for (i=0; i<len; i++) {
    printf ("%02x", ((uint8_t*)tek)[i]);
  }
#endif
}
void aes_ctr_encrypt(spp_ctx *c, void *data, uint32_t len);

void show_keys(spp_ctx *c) {
#if defined(DEBUG) && DEBUG > 0
  int i;
  spp_len magic;
  uint8_t mac[SPP_MAC_LEN];
  
  memset((uint8_t*)&magic, 0, sizeof(magic));
  
  printf ("\nAES Key : ");
  for (i=0; i<SPP_EKEY_LEN; i++) {
    printf ("%02x", c->tek.ekey[i]);
  }
  printf ("\nMAC Key : ");
  for (i=0; i<SPP_MKEY_LEN; i++) {
    printf ("%02x", c->tek.mkey[i]);
  }
  printf ("\nAES CTR : ");
  for (i=0; i<SPP_CTR_LEN; i++) {
    printf ("%02x", c->tek.ctr[i]);
  }
  /*spp_mac(c, &magic, 4, mac);
  spp_dump(mac, 16, "mac");
  
  memset((uint8_t*)&magic, 0, sizeof(magic));
  spp_dump((uint8_t*)&magic, 16, "before enc");
  
  aes_ctr_encrypt(c, (uint8_t*)&magic, sizeof(magic));
  spp_dump((uint8_t*)&magic, 16, "after enc");
  
  aes_ctr_encrypt(c, (uint8_t*)&magic, sizeof(magic));
  spp_dump((uint8_t*)&magic, 16, "after dec");*/
#endif
}

/**F*********************************************
 *
 * entrypoint of PIC
 *
 ************************************************/
int spp_rand (spp_ctx *c, void *out, uint32_t outlen)
{
  BIGNUM *r = BN_new();
  
  // create random bits
  BN_rand(r, outlen*8, -1, 0);
  BN_bn2bin(r, out);
  BN_free(r);
  
  return 1;
}

/**F*********************************************
 *
 * Pad SPP data buffer with random bytes
 *
 ************************************************/
void spp_pad (spp_ctx *c, spp_blk *x)
{
  x->len.padlen = (x->len.buflen & (SPP_BLK_LEN-1));
  
  // if not zero
  if (x->len.padlen) {
    // calculate how much padding bytes required
    x->len.padlen = (SPP_BLK_LEN - x->len.padlen);
    
    // generate random bytes
    spp_rand (c, &x->data.b[x->len.buflen], x->len.padlen);
    
    // update block len to include padding
    x->len.buflen += x->len.padlen;
  }
}
/**F*********************************************
 *
 * TODO: sign keys
 *
 ************************************************/
int spp_sign (spp_ctx *c, spp_blk *in)
{
  // 
  return 1;
}

/**F*********************************************
 *
 * TODO: verify keys
 *
 ************************************************/
int spp_verify (spp_ctx *c, spp_blk *in)
{
  //
  return 1;
}

/**F*********************************************
 *
 * Generate MAC of encrypted packet
 *
 ************************************************/
void spp_mac (spp_ctx *c, void *data, uint32_t data_len, void *mac)
{
  SHA3_CTX ctx;
  uint8_t  m[SHA3_256];
  int      i;
  
  DEBUG_PRINT("Generating MAC for %i bytes of data", data_len);
  spp_dump(data, data_len, "mac data");
  
  SHA3_Init(&ctx, SHA3_256);
  SHA3_Update(&ctx, c->tek.mkey, SPP_MKEY_LEN);
  SHA3_Update(&ctx, data, data_len);
  SHA3_Final(m, &ctx);
  
  memcpy(mac, m, SPP_MAC_LEN);
}

/**F*********************************************
 *
 * xor block of plaintext with ciphertext
 *
 ************************************************/
uint32_t memxor (uint8_t *pt, uint8_t *ct, uint32_t len)
{
  uint32_t i;
  
  len=(len>SPP_BLK_LEN) ? SPP_BLK_LEN:len;
  
  for (i=0; i<len; i++) {
    pt[i] ^= ct[i];
  }
  return len;
}

/**F*********************************************
 *
 * increase the counter block
 *
 ************************************************/
void update_ctr (uint8_t *ctr)
{
  int i;
  
  for (i=SPP_CTR_LEN-1; i>=0; i--) {
    ctr[i]++;
    if (ctr[i]) {
      break;
    }
  }
}

void aes_ctr_encrypt(spp_ctx *c, void *data, uint32_t len)
{
  uint32_t i, r, inlen=len;
  uint8_t  *p=(uint8_t*)data;
  uint8_t  ctr[SPP_CTR_LEN];
  
  DEBUG_PRINT("Decrypting/Encrypting %i bytes", len);
  spp_dump(data, len, "enc data");
  
  while (inlen)
  {
    // copy counter into temp space
    memcpy (ctr, c->tek.ctr, SPP_CTR_LEN);
    
    // encrypt with AES-256 in ECB mode
    AES_encryptx (ctr, ctr, &c->ctx, AES_ENCRYPT);
      
    // xor against plaintext
    r=memxor (p, ctr, inlen);
    
    // update counter
    update_ctr(c->tek.ctr);
   
    // advance plaintext position
    p += r;
    
    // decrease length of input
    inlen -= r;
  }
}

/**F*********************************************
 *
 * Encrypt packet, using AES in CTR mode
 *
 ************************************************/
int spp_crypt (spp_ctx *c, void *data, uint32_t len, int enc)
{
  uint8_t mac[SPP_MAC_LEN];
  uint8_t *p=(uint8_t*)data;
  uint32_t data_len=len;
  
  DEBUG_PRINT("Entering spp_crypt with %i bytes", len);
  
  if (enc==SPP_DECRYPT)
  {
    // subtract MAC length
    data_len -= SPP_MAC_LEN;
    
    // generate MAC of encrypted data
    spp_mac (c, data, data_len, mac);
    
    // compare if equal
    if (memcmp (mac, &p[data_len], SPP_MAC_LEN)!=0) {
      return SPP_ERR_MAC;
    }
  }
  // encrypt or decrypt data
  aes_ctr_encrypt (c, data, data_len);
    
  if (enc==SPP_ENCRYPT)
  {
    // add mac of encrypted data
    spp_mac (c, data, data_len, &p[data_len]);
    data_len += SPP_MAC_LEN;
  }
  DEBUG_PRINT("Leaving spp_crypt with %i bytes", data_len);
  return data_len;
}

/**F*********************************************
 *
 * send packet, fragmented if required
 *
 ************************************************/
int send_pkt (int s, void *in, uint32_t inlen)
{
  int      len;
  uint32_t sum;
  uint8_t  *p=(uint8_t*)in;
  
  for (sum=0; sum<inlen; sum += len) {
    len=send (s, &p[sum], inlen - sum, 0);
    if (len<=0) return -1;
  }
  return sum;
}

/**F*********************************************
 *
 * send data, encrypted if required
 *
 ************************************************/
int spp_send (spp_ctx *c, spp_blk *in)
{
  int      len;
  uint32_t data_len = in->len.w;
  
  DEBUG_PRINT("entering spp_send to send %i bytes", data_len);
  
  // 1. if not secure mode, goto step 3
  if (c->secure) {
    if (data_len) in->len.w += SPP_MAC_LEN; // for data
    // 2. encrypt the length, add mac
    len = spp_crypt (c, in->len.b, sizeof(int), SPP_ENCRYPT);
  }
  // 3. send length
  len = send_pkt (c->s, in->len.b, sizeof(spp_len));
  
  // 4. if no data, goto step 8
  if (data_len)
  {
    // 5. if not secure mode, goto step 7
    if (c->secure) {
      // 6. encrypt data
      data_len = spp_crypt (c, in->data.b, data_len, SPP_ENCRYPT);
    }
    // 7. send data
    len = send_pkt (c->s, in->data.b, data_len);
  }  
  DEBUG_PRINT("leaving spp_send after sending %i bytes", 
      data_len + sizeof(spp_len));
  
  // 8. return OK if no error
  return (len < 0) ? SPP_ERR_SCK : SPP_ERR_OK;
}

/**F*********************************************
 *
 * receive packet, fragmented if required
 *
 ************************************************/
int recv_pkt (int s, void *out, uint32_t outlen) 
{
  int      len;
  uint32_t sum;
  uint8_t  *p=(uint8_t*)out;

  for (sum=0; sum<outlen; sum += len) {
    len=recv (s, &p[sum], outlen - sum, 0);
    if (len<=0) return -1;
  }
  return sum;
}

/**F*********************************************
 *
 * receive data, decrypt if required
 *
 ************************************************/
int spp_recv (spp_ctx *c, spp_blk *out)
{
  int len;
  
  DEBUG_PRINT("entering spp_recv");
  
  // 1. receive the length first
  len=recv_pkt (c->s, &out->len.w, sizeof(spp_len));

  // 2. if socket error, return SCK error
  if (len <= 0) {
    DEBUG_PRINT("recv_pkt socket error");
    return SPP_ERR_SCK;
  }
  
  // 3. if not secure, goto step 6
  if (c->secure) {
    // 4. decrypt length and verify mac
    len=spp_crypt(c, out->len.b, sizeof(spp_len), SPP_DECRYPT);
    // 5. if decryption error, return ENC error
    if (len < 0) {
      DEBUG_PRINT("spp_crypt error");
      return SPP_ERR_ENC;
    }
    DEBUG_PRINT("buf len = %i len = %i", out->len.buflen, len);
  }
  
  // 6. if zero length, return OK
  if (out->len.buflen == 0) {
    DEBUG_PRINT("buflen is zero");
    return SPP_ERR_OK;
  }

  // 7. if buflen problem, return LEN error
  if (out->len.buflen > SPP_DATA_LEN+SPP_MAC_LEN) {
    DEBUG_PRINT("buflen exceeds max allowed");
    return SPP_ERR_LEN;
  }

  // 8. if padlen problem, return LEN error
  if (out->len.padlen >= SPP_BLK_LEN) {
    DEBUG_PRINT("padlen exceeds max allowed");
    return SPP_ERR_LEN;
  }
  
  // 9. receive the data
  len=recv_pkt (c->s, &out->data.b, out->len.buflen);
  
  // 10. if socket error, return SCK error
  if (len<=0) {
    DEBUG_PRINT("recv_pkt error for data");
    return SPP_ERR_SCK;
  }
  
  // 11. if not secure, goto step 14
  if (c->secure) {
    // 12. decrypt the data, verify mac
    len=spp_crypt(c, out->data.b, out->len.buflen, SPP_DECRYPT);
    // 13. if decryption error, return ENC error
    if (len<=0) {
      DEBUG_PRINT("spp_crypt error for data");
      return SPP_ERR_ENC;
    }
    out->len.buflen = len;
    DEBUG_PRINT("buf len = %i len = %i", out->len.buflen, len);
  }
  
  /* remove any padding
  x->v.blk.buflen -= x->v.blk.padlen;
  x->v.blk.padlen = 0;
  
  x->v.blk.buf[x->v.blk.buflen]=0;*/
  
  DEBUG_PRINT("leaving spp_recv");
  // 14. return OK if no errors
  return (len<=0) ? SPP_ERR_SCK : SPP_ERR_OK;
}

/**F*********************************************
 *
 * TODO: read external key pair
 *
 ************************************************/
int spp_readkey (spp_ctx *c, spp_blk *key)
{
  //
  return 1;
}

/**F*********************************************
 *
 * initialize spp
 *
 ************************************************/
int spp_init (spp_ctx *c)
{
  RSA     *rsa;
  int     r = 1;
  c->secure = 0;
  
  // create BIGNUM for e, d and n
  c->e      = BN_new();
  c->d      = BN_new();
  c->n      = BN_new();
  c->bn_ctx = BN_CTX_new();
  
  // create new RSA object
  rsa       = RSA_new();
  
  // set exponent
  BN_dec2bn(&c->e, "65537");
  
  // generate RSA key pair
  RSA_generate_key_ex(rsa, SPP_RSA_LEN, c->e, NULL);
  
  // copy private key and modulus
  BN_copy(c->d, rsa->d);
  BN_copy(c->n, rsa->n);
  
  // free RSA object
  RSA_free(rsa);
  
  return r;
}

/**F*********************************************
 *
 * get the public key from context as binary
 *
 ************************************************/
int spp_getkey(spp_ctx *c, spp_blk *out)
{
  int i, rs;
  
  // get length of modulus in bytes
  out->len.w=BN_num_bytes(c->n);
  
  // copy public key to buffer
  memcpy (out->data.b, c->n->d, out->len.w);
  
  DEBUG_PRINT ("\nModulus is %s", BN_bn2hex(c->n));
  
  // attach signature for client to verify
  rs=spp_sign (c, out);
    
  return rs;
}

/**F*********************************************
 *
 * set the AES key, Nonce or MAC key
 *
 ************************************************/
int spp_setkey(spp_ctx *c, spp_blk *in)
{
  int    r=1, i;
  BIGNUM *keys, *enc;

  // import session keys
  enc  = BN_new();
  keys = BN_new();
  
  DEBUG_PRINT ("\nreceived %i bytes", in->len.w);
  // use little endian function for PIC
  BN_lebin2bn (in->data.b, in->len.w, enc);
  DEBUG_PRINT ("\nEncrypted keys are %s", BN_bn2hex(enc));

  // decrypt using private key
  BN_mod_exp (keys, enc, c->d, c->n, c->bn_ctx);

  DEBUG_PRINT ("\nSession keys are %s", BN_bn2hex(keys));
  // copy 512-bits of key
  memcpy ((uint8_t*)&c->tek, keys->d, SPP_TEK_LEN);
  // set AES-256 key
  AES_setkey (c->tek.ekey, &c->ctx);

  show_keys(c);
  
  BN_free(enc);
  BN_free(keys);
    
  return r;
}

/**F*********************************************
 *
 * perform key exchange with client
 *
 ************************************************/
int spp_handshake (spp_ctx *c)
{
  int     r=0;
  spp_blk pubkey, seskey, iv;
  
  // get the public key
  printf ("[ getting public key\n");
  if (spp_getkey(c, &pubkey))
  {
    // send to client
    printf ("[ sending public key\n");
    if (spp_send(c, &pubkey)==SPP_ERR_OK)
    {
      // wait for session key
      printf ("[ receiving session keys\n");
      if (spp_recv(c, &seskey)==SPP_ERR_OK)
      {
        // import it
        printf ("[ importing session keys\n");
        r=spp_setkey(c, &seskey);
      }
    }
  }
  // if no error, set secure flag
  if (r) { 
    //spp_showkeys(c);
    c->secure=1; 
  }
  return r;
}

/**F*********************************************
 *
 * clean up
 *
 ************************************************/
void spp_end (spp_ctx *c)
{
  DEBUG_PRINT ("\nfreeing d");
  BN_free(c->d);
    
  DEBUG_PRINT ("\nfreeing e");
  BN_free(c->e);
    
  DEBUG_PRINT ("\nfreeing ctx");
  BN_CTX_free(c->bn_ctx);
}

