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

#include "tlscmd.h"

void tls_cmd (tls_ctx *ctx, tls_session *tls); 

void tls_client(tcp_ctx *tcp, tls_ctx *ctx)
{
  tls_session *tls = tls_new_session(ctx);
  FD_SET      fds;
  int         r;
  
  if (tls != NULL) {
    // open connection to remote host
    if (connect(
      tcp->s, tcp->ai_addr, 
      tcp->ai_addrlen)!=SOCKET_ERROR)
    {
      // set socket descriptor
      tls->sck = tcp->s;
      if (tls_handshake(ctx, tls)) {
        DEBUG_PRINT ("\n  [ connected");
        
        #if defined(DEBUG) && DEBUG > 0 
          tls_info(ctx, tls, TLS_CONNECTION_INFO); 
          tls_info(ctx, tls, TLS_STREAM_SIZE);  
        #endif
        
        tls_cmd(ctx, tls);
      } else {
        DEBUG_PRINT("\n  [ handshake failed"); 
      }
      shutdown(tcp->s, SD_BOTH);
      closesocket(tcp->s);
    } else {
      DEBUG_PRINT("\n  [ connect failed");
    }
    tls_free_session(ctx, tls);    
  }
}

int main(int argc, char *argv[])
{
  tcp_ctx *tcp;
  tls_ctx *ctx;
  char    *host, *port;
  
  if (argc != 3) {
    printf("\nusage: tlscmd <host> <port>\n");
    return 0;
  }
  
  host = argv[1];
  port = argv[2];
  
  printf ("\n  [ connecting to %s:%i...", host, atoi(port));
  tcp = tcp_new_ctx(AF_INET, host, port);
  if (tcp!=NULL) {
    printf ("\n  [ host resolved to %s", tcp_addr2ip(tcp));
    ctx = tls_new_ctx();
    if (ctx!=NULL) {
      printf ("\n  [ TLS client initialized");
      tls_client(tcp, ctx);
      tls_free_ctx(ctx);
    }
    tcp_free_ctx(tcp);
  }
  return 0;
}
