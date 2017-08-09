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
  
#ifndef S5_H
#define S5_H

#include "spp.h"

#define DEFAULT_PORT 1234 // as client or server

typedef struct _spp_opt_t {
  int cmd;
  char *s;
} spp_opt;

// structure for parameters
typedef struct _args_t {
  int       s, r;
  char      *port, *address, *file;
  int       port_nbr, ai_family, mode, tx_mode;
  socklen_t ai_addrlen;
  struct    sockaddr *ai_addr;
  struct    sockaddr_in v4;
  struct    sockaddr_in6 v6;
  char      ip[INET6_ADDRSTRLEN];
} args_t;

char* getparam (int argc, char *argv[], int *i);
void parse_args (args_t *p, int argc, char *argv[]);
void cmd (spp_ctx*);
void xstrerror (char*, ...);
char *addr2ip (args_t*);
void usage (void);
void client (args_t*);
void server (args_t*);

#ifdef WIN
DWORD wait_evt (HANDLE*, DWORD, DWORD, SOCKET);
typedef struct _INPUT_DATA {
  DWORD  len;
  char   buf[SPP_DATA_LEN+64];
  HANDLE evt, evtbck;
} INPUT_DATA, *PINPUT_DATA;
#endif

#endif
