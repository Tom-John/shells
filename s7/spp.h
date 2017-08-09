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

#ifndef SPP_H
#define SPP_H

#if defined(_WIN32) || defined(_WIN64)
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

#define close closesocket
#define sleep Sleep
#define SHUT_RDWR SD_BOTH

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "gdi32.lib")
#endif

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

#include "crypto.h"

#define SPP_MAC_LEN   TAG_LENGTH
#define SPP_BLK_LEN   BLOCK_LENGTH*8
#define SPP_EKEY_LEN  BC_KEY_LENGTH
#define SPP_MKEY_LEN  LIGHTMAC_KEY_LENGTH
#define SPP_CTR_LEN   BLOCK_LENGTH
#define SPP_ENCRYPT   CRYPT_ENCRYPT
#define SPP_DECRYPT   CRYPT_DECRYPT

#define SPP_ERR_OK    0
#define SPP_ERR_SCK   -1
#define SPP_ERR_LEN   -2
#define SPP_ERR_MAC   -3
#define SPP_ERR_ENC   -4

typedef union _spp_len_t {
  uint8_t  b[sizeof(uint32_t)+SPP_MAC_LEN];
  uint32_t w;
  struct {
    uint16_t buflen;
    uint16_t padlen;
  };
} spp_len;

// spp data type
typedef union _spp_data_t {
  uint8_t b[SPP_BLK_LEN+SPP_MAC_LEN];
} spp_data;

// spp packet structure
typedef struct _spp_buf_t {
  spp_len  len;
  spp_data data;
} spp_buf;

// packet protocol context
typedef struct _spp_ctx_t {
  int        s;  // holds socket descriptor/handle
  crypto_ctx cc; // holds mac+encryption keys
} spp_ctx;

#ifdef __cplusplus
extern "C" {
#endif

  int spp_recv (spp_ctx*, spp_buf*);
  int spp_send (spp_ctx*, spp_buf*);

#ifdef __cplusplus
}
#endif

#endif
