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
  
#ifndef MODEXP_H
#define MODEXP_H

#include <stdint.h>

#define BIT_LEN 8192  // increase as needed
#define BUF_LEN (BIT_LEN/8) + 4

typedef uint32_t bn_word;

// big number array
typedef union _bn_t {
  uint8_t v8[BUF_LEN];
  uint16_t v16[BUF_LEN/2];
  uint32_t v32[BUF_LEN/4];
  uint64_t v64[BUF_LEN/8];
} bn;

typedef union _bw_t {
  uint32_t v32;
  struct {
    uint16_t lo;
    uint16_t hi;
  };
} bw;

typedef union _bd_t {
  uint64_t v64;
  struct {
    uint32_t lo;
    uint32_t hi;
  };
} bd;
  
#ifdef __cplusplus
extern "C" {
#endif

int bn_bt(bn*, uint32_t);
int bn_bits(bn*);
int bn_bytes(bn*);

void bn_zero(bn*);
void bn_copy(bn*, bn*);

void bn_add(bn*, bn*, bn*);
void bn_sub(bn*, bn*, bn*);
int bn_cmp(bn*, bn*);

void bn_addmod(bn*, bn*, bn*, bn*);
void bn_mulmod(bn*, bn*, bn*, bn*);
void bn_expmod(bn*, bn*, bn*, bn*);

void bn_reverse (bn*);

#ifdef __cplusplus
}
#endif

#endif