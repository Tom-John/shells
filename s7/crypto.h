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

#ifndef CRYPTO_H
#define CRYPTO_H

#include "macros.h"

//#define DEBUG 1

#if defined(DEBUG) && DEBUG > 0
 #define DEBUG_PRINT(...) { \
   fprintf(stderr, "\nDEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DEBUG_PRINT(...) /* Don't do anything in release builds */
#endif

#define COUNTER_LENGTH 4
#define TAG_LENGTH     8
#define BLOCK_LENGTH   8
#define BC_KEY_LENGTH 16

#define LIGHTMAC_KEY_LENGTH BC_KEY_LENGTH*2

// undefine for msvc/mingw
#undef CRYPT_ENCRYPT
#undef CRYPT_DECRYPT

#define CRYPT_ENCRYPT 0
#define CRYPT_DECRYPT 1

typedef union bc_blk_t {
  uint32_t ctr;
  uint8_t  b[BLOCK_LENGTH];
  uint32_t w[BLOCK_LENGTH/sizeof(uint32_t)];
} bc_blk;

typedef union _w32_t {
  uint8_t b[4];
  uint32_t w;	
} w32_t;

typedef union _w64_t {
  uint8_t  b[8];
  uint32_t w[2];	
} w64_t;

typedef union _w128_t {
  uint8_t b[16];
  uint32_t w[4];	
} w128_t;

typedef struct crypto_ctx_t {
  uint8_t  e_ctr[BLOCK_LENGTH];        // block encryption counter
  uint8_t  e_key[BC_KEY_LENGTH];       // block encryption key  
  uint8_t  m_key[LIGHTMAC_KEY_LENGTH]; // mac key 
} crypto_ctx;

#ifdef __cplusplus
extern "C" {
#endif

  void speck64_encrypt(const void*, void*);
  
  int encrypt(crypto_ctx*, void*, uint32_t, int);
  int encryptx(crypto_ctx*, void*, uint32_t, int);
  
  void lightmac_tag(crypto_ctx*, void*, uint32_t, void*); 
  void lightmac_tagx(crypto_ctx*, void*, uint32_t, void*); 

#ifdef __cplusplus
}
#endif

#endif
