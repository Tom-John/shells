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

#ifndef SPP_H
#define SPP_H

#ifdef _MSC_VER
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0502
#endif
#define WIN
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_  
#endif
#include <windows.h>
#include <shlwapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

//#define close closesocket
#define sleep Sleep
#define SHUT_RDWR SD_BOTH

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "gdi32.lib")

#else

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "sha3.h"
#include "aes.h"

//#define DEBUG 1

#if defined(DEBUG) && DEBUG > 0
 #define DEBUG_PRINT(...) { \
   fprintf(stderr, "\nDEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DEBUG_PRINT(...) /* Don't do anything in release builds */
#endif

#define SPP_DATA_LEN  2048     // in bytes
#define SPP_RSA_LEN   2048     // in bits
#define SPP_MAC_LEN   12
#define SPP_BLK_LEN   16
#define SPP_SIG_LEN   SPP_RSA_LEN/8

#define SPP_EKEY_LEN  32
#define SPP_MKEY_LEN  16
#define SPP_CTR_LEN   16
#define SPP_NONCE_LEN 12
#define SPP_TEK_LEN   SPP_EKEY_LEN+SPP_MKEY_LEN+SPP_CTR_LEN

#define SPP_CMD_SHELL 1
#define SPP_CMD_PUT   2
#define SPP_CMD_GET   3
#define SPP_CMD_TERM  4
#define SPP_CMD_CLOSE 5
#define SPP_CMD_HELP  6
#define SPP_CMD_LIST  7
#define SPP_CMD_RLIST 8

#define SPP_ERR_OK    0
#define SPP_ERR_SCK   -1
#define SPP_ERR_LEN   -2
#define SPP_ERR_MAC   -3
#define SPP_ERR_ENC   -4

#define SPP_ENCRYPT 0
#define SPP_DECRYPT 1

#pragma pack(1)
// spp length
typedef union _spp_len_t {
  uint8_t  b[sizeof(uint32_t)+SPP_MAC_LEN];
  uint32_t w;
  struct {
    uint16_t buflen;
    uint16_t padlen;
  };
} spp_len;

// spp command structure
typedef struct _spp_cmd_t {
  uint32_t opt;
  uint8_t  buf[SPP_DATA_LEN+SPP_MAC_LEN];
} spp_cmd;

// spp file transfer structure
typedef struct _spp_fx_t {
  uint32_t err;
  uint64_t size;
} spp_fx;

// spp data type
typedef union _spp_data_t {
  spp_cmd cmd;
  spp_fx  fx;
  uint8_t b[SPP_DATA_LEN+SPP_MAC_LEN];
} spp_data;

// spp packet structure
typedef struct _spp_blk_t {
  spp_len  len;
  spp_data data;
} spp_blk;

// traffic encryption keys
typedef struct _spp_tek_t {
  uint8_t ekey[SPP_EKEY_LEN];   // 256-bit symmetric key for encryption
  uint8_t ctr[SPP_CTR_LEN];     // 128-bit block counter
  uint8_t mkey[SPP_MKEY_LEN];   // 128-bit key for message authentication
  uint8_t pad[SPP_DATA_LEN];
} spp_tek;

// file transfer structure for server
typedef struct _spp_tx_t {
  char src[MAX_PATH];        // source of file
  char dst[MAX_PATH];        // destination
} spp_tx;

// packet protocol context
typedef struct _spp_ctx_t {
  int        s;              // holds socket descriptor/handle
  uint32_t   secure;
  spp_tek    tek;            // transport encryption keys
  aes_ctx    ctx;
  BIGNUM     *e, *d, *n;
  BN_CTX     *bn_ctx;
} spp_ctx;

  int spp_send (spp_ctx*, spp_blk*);
  int spp_recv (spp_ctx*, spp_blk*);
  
  int spp_init (spp_ctx*);
  int spp_handshake (spp_ctx*);
  void spp_end (spp_ctx*);
  
  int spp_setkey (spp_ctx*, spp_blk*);
  int spp_getkey(spp_ctx*, spp_blk*);

  int spp_rand (spp_ctx*, void*, uint32_t);
  void spp_pad (spp_ctx*, spp_blk*);
  int spp_sign (spp_ctx*, spp_blk*);
  int spp_verify (spp_ctx*, spp_blk*);
  void spp_mac (spp_ctx*, void*, uint32_t, void*);
  int spp_crypt (spp_ctx*, void*, uint32_t, int);
  
#endif
