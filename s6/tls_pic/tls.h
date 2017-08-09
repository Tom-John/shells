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

#ifndef TLS_H
#define TLS_H

#include "tlscmd.h"

#pragma comment(lib, "crypt32.Lib")
#pragma comment(lib, "ws2_32.Lib")

#define TLS_MAX_BUFSIZ 32768

#define TLS_CONNECTION_INFO SECPKG_ATTR_CONNECTION_INFO
#define TLS_STREAM_SIZE     SECPKG_ATTR_STREAM_SIZES

typedef struct tls_ctx_t {
  SECURITY_STATUS           ss;
	HMODULE                   lib;
	PSecurityFunctionTable    sspi;
	HCERTSTORE                cert;
  SecPkgContext_StreamSizes sizes;
} tls_ctx;

typedef struct tls_session_t {
	int                 established, start, sck, secure;
	int                 failed, read_alerts, write_alerts;

	SCHANNEL_CRED       sc;
	CredHandle          cc;
	CtxtHandle          ctx;
  TimeStamp           ts;
  SecBuffer           pExtra;
  
  uint8_t             *buf;
  DWORD               buflen, maxlen;
  char                *address, *port;
  int                 s, ai_addrlen;
  struct sockaddr     *ai_addr;
  struct sockaddr_in  v4;
  struct sockaddr_in6 v6;  
  char                ip[INET6_ADDRSTRLEN];   
} tls_session;

typedef struct alg_info_t {
  ALG_ID id;
  char *s;
} alg_info;

#ifdef __cplusplus
extern "C" {
#endif

  void* tls_alloc (int);
  void* tls_realloc (void*, int);
  void tls_free (void*);

  int tls_load_lib(tls_ctx*);

  tls_ctx* tls_new_ctx(void);
  void tls_free_ctx(tls_ctx*);

  tls_session* tls_new_session(tls_ctx *c);
  void tls_free_session(tls_ctx*, tls_session*);

  int tls_hello(tls_ctx*, tls_session*);
  int tls_handshake(tls_ctx*, tls_session*);

  int tls_encrypt(tls_ctx*, tls_session*);
  int tls_decrypt(tls_ctx*, tls_session*);

  void tls_info (tls_ctx*, tls_session*, int);

  int tls_recv(int, void*, uint32_t);
  int tls_send(int, void*, uint32_t);

#ifdef __cplusplus
}
#endif

#endif
