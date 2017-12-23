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
  
#include "s7.h"

#ifdef WIN

INPUT_DATA input;

/**F***********************************************/
static DWORD WINAPI stdin_thread (LPVOID param)
/**
 * PURPOSE : Read input from console, signal event when available
 *
 * RETURN :  Nothing
 *
 * NOTES :   None
 *
 *F*/
{
    BOOL   bRead;
    HANDLE stdinput=GetStdHandle (STD_INPUT_HANDLE);
    
    for (;;)
    {
      bRead=ReadFile (stdinput, input.buf, 
        SPP_BLK_LEN, &input.len, NULL);
        
      // bRead is only FALSE if there was error
      if (!bRead) break;
      
      if (input.len > 0) {
        input.buf[input.len]=0;
        SetEvent (input.evt);
        WaitForSingleObject (input.evtbck, INFINITE);
      }
    }

    input.len = 0;
    SetEvent (input.evt);
    return 0;
}

/**F*********************************************
 *
 * entrypoint of PIC
 *
 ************************************************/
DWORD wait_evt (HANDLE *evt, DWORD evt_cnt, 
  DWORD sck_evt, SOCKET s)
{
    WSANETWORKEVENTS ne;
    DWORD            e;
    u_long           opt;
    
    // set socket to non-blocking mode
    WSAEventSelect (s, evt[sck_evt], FD_CLOSE | FD_READ);
    // wait for read/close events on socket + termination of cmd.exe
    e=WaitForMultipleObjects (evt_cnt, evt, FALSE, INFINITE);
    // enumerate events on socket
    WSAEnumNetworkEvents (s, evt[sck_evt], &ne);
    // disable events on socket  
    WSAEventSelect (s, evt[sck_evt], 0);
    // set to blocking mode
    opt=0;
    ioctlsocket (s, FIONBIO, &opt);
    // socket closed?
    if (ne.lNetworkEvents & FD_CLOSE) {
      e = ~0UL;
    }
    return e;
}

/**F********************************************/
void session (spp_ctx *c)
/**
 * PURPOSE : Sends commands to remote client
 *
 * RETURN :  Nothing
 *
 * NOTES :   None
 *
 *F*/
{
    HANDLE  hThread, stdoutput;
    HANDLE  evt[MAXIMUM_WAIT_OBJECTS];
    DWORD   e, wn, stdin_evt=0, sck_evt=0, evt_cnt=0;
    spp_buf in, out;  
    
    // create 2 events for reading input
    // this is necessary because STD_INPUT_HANDLE also
    // signals for events other than keyboard input
    // and consequently blocks when ReadFile() is called.
    // the solution is to create separate thread.
    // UNIX-variant OS don't suffer from this issue.
    input.evt    = CreateEvent (NULL, FALSE, FALSE, NULL);
    input.evtbck = CreateEvent (NULL, FALSE, FALSE, NULL);
    
    // event for input
    evt[stdin_evt = evt_cnt++] = input.evt;
    // event for socket
    evt[sck_evt   = evt_cnt++] = WSACreateEvent();
    // obtain handle to stdout
    stdoutput=GetStdHandle (STD_OUTPUT_HANDLE);
    
    // create thread for reading input
    hThread=CreateThread (NULL, 0, 
        stdin_thread, NULL, 0, NULL);
              
    for (;;) {
      DEBUG_PRINT("waiting for events");
      // wait for events
      e=wait_evt(evt, evt_cnt, sck_evt, c->s);
      
      // failure? break
      if (e==-1) {
        break;
      }
      
      // read from socket?
      if (e == sck_evt) 
      {
        DEBUG_PRINT("reading from socket");
        // receive packet, break on error
        if (spp_recv (c, &in) != SPP_ERR_OK) {
          DEBUG_PRINT("[ spp_recv() error\n");
          break;
        }
        // else we're still interactive, write to console
        WriteConsole (stdoutput, 
            in.data.b, in.len.w, &wn, 0);
      } else {
        DEBUG_PRINT("sending data");
        // we're in cmd_mode, copy input to packet buffer
        out.len.w = input.len;
        memcpy (out.data.b, input.buf, input.len);
        // remove carriage return if remote is NIX
        out.data.b[input.len-2] = '\n';
        out.data.b[input.len] = 0;
        out.len.w--;
        // send to cmd.exe on client
        spp_send(c, &out);
          
        // start reading user input again
        SetEvent (input.evtbck);
      }
    }
    
    printf ("[ cleaning up\n");
    
    CloseHandle (hThread);
    CloseHandle (input.evtbck);
    CloseHandle (input.evt); 
    CloseHandle (evt[sck_evt]); 
}
#else

int              pfd[2];
struct sigaction handler;

int sig(int code)
{
  write (pfd[1], ".", 1);  
  return 1;
}

void install_handler(void)
{
  pipe (pfd);              
  handler.sa_handler = (void (*)(int))sig;
  sigemptyset(&handler.sa_mask);
  handler.sa_flags = 0;
  sigaction (SIGINT, &handler, NULL); 
}

void session(spp_ctx *c)
{
    fd_set  fds;
    int     r, len;
    spp_buf x;
    
    install_handler();
    
    for (;;) {
      FD_ZERO(&fds);
      FD_SET(STDIN_FILENO, &fds);
      FD_SET(pfd[0], &fds);
      FD_SET(c->s, &fds);
      
      r=select(FD_SETSIZE, &fds, 0, 0, 0);
      if (r<=0) break;
      
      if (FD_ISSET(STDIN_FILENO, &fds)) 
      {
        len=read(STDIN_FILENO, x.data.b, SPP_BLK_LEN);
        x.len.w=len;
        if (spp_send(c, &x) != SPP_ERR_OK) break;
      } else if (FD_ISSET(c->s, &fds)) {
        if (spp_recv(c, &x) != SPP_ERR_OK) break;
        write(STDOUT_FILENO, x.data.b, x.len.w);    
      } else if (FD_ISSET(pfd[0], &fds)) {
        printf ("\nCTRL+C received");
        break;
      }
    }
    shutdown(c->s, SHUT_RDWR);
    close(c->s);
}  

#endif
  
void server(args_t *p)
{
    spp_ctx c;
    int     t;
    
    memset(&c, 0, sizeof(c));
    
    // bind to local address
    printf ("[ binding to %s\n", addr2ip(p));
    if (bind (p->s, p->ai_addr, p->ai_addrlen) != -1) 
    {
      // listen for incoming connections
      printf ("[ listening for connections\n");
      if (listen (p->s, SOMAXCONN) != -1) 
      {
        printf ("[ waiting for connections on %s\n", addr2ip(p));
        p->r=accept (p->s, p->ai_addr, &p->ai_addrlen);
        
        if (p->r != -1) {
          printf ("[ connection from %s\n\n", addr2ip(p));
          
          t   = c.s;
          c.s = p->r;
          
          session(&c);
          
          shutdown (p->r, SHUT_RDWR);
          close(p->r);
          c.s=t;
        } else {
          xstrerror ("accept()");
        }       
      } else {
        xstrerror ("listen()");
      }
    } else {
      xstrerror ("bind()");
    }
}

void client(args_t *p)
{
    spp_ctx c;

    memset(&c, 0, sizeof(c));
    
    // connect to local address
    printf ("[ connecting to %s\n", addr2ip(p));
    
    if (!(connect (p->s, p->ai_addr, p->ai_addrlen))) 
    {
      c.s = p->s;
      session(&c);
    } else {
      xstrerror ("connect()");
    }
}
