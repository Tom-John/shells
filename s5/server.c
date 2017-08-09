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
  
#include "s5.h"

INPUT_DATA input;

spp_opt cmds[]=
{ {SPP_CMD_HELP,  "help" },
  {SPP_CMD_HELP,  "?"    },
  {SPP_CMD_TERM,  "exit" },
  {SPP_CMD_LIST,  "ls"   },
  {SPP_CMD_SHELL, "cmd"  },
  {SPP_CMD_PUT,   "put"  },
  {SPP_CMD_GET,   "get"  }
};

// dodgy string parser ;-)
// just simple parsing of paths
// it does the job but it might break with bad input
// not used on client side so should be okay
char* get_string (char *path)
{
  int         qm=0, cnt=0;
  static char buf[BUFSIZ], *s;
  static      size_t pos, len;
  char        c;
  size_t      i=0;
  
  // if not null, use previous string provided
  if (path!=NULL) {
    s=path;
    len=strlen (path);
  }
  memset (buf, 0, sizeof buf);
  
  // for length of string past initial bytes
  while (*s != 0) 
  {
    // get byte
    c=*s++;
    // if quotation marks? toggle qm, break if zero else continue
    if (c=='\"') { qm=!qm; if (!qm) { break;} else continue; }
    // continue if white space
    if (c=='\t' || c=='\r' || c=='\n') { continue; }
    // break if space and j is not zero
    if (c==' ' && qm==0) {
      if (i!=0) {
        break;
      }
    } else {
      // save it
      buf[i++]=c;
    }
  }
  return i==0 ? NULL : buf;
}

/**F*****************************************************************/
int parse_path (char *path, spp_tx *tx) 
/**
 * PURPOSE : split command
 *
 * RETURN :  -1 on error else SPP_GET_CMD or SPP_PUT_CMD
 *
 * NOTES :   None
 *
 *F*/
{
  char *p;
  int  i, mode;
  char *paths[2];
  
  memset (tx->src, 0, MAX_PATH);
  memset (tx->dst, 0, MAX_PATH);
  
  paths[0]=tx->src; 
  paths[1]=tx->dst;
  
  // check command
  p=get_string (path);
  if (p==NULL) {
    return -1;
  }
  
  // get command?
  if (strcmp ("get", p)==0) {
    mode=SPP_CMD_GET;
  } else if (strcmp ("put", p)==0) {
    mode=SPP_CMD_PUT;
  } else {
    return -1;
  }
  // get at most, 2 strings
  for (i=0; i<2 && p!=NULL; i++)
  {
    p=get_string(NULL);
    if (p==NULL) break;
    strncpy (paths[i], p, MAX_PATH);
  }
  // no source provided?
  if (i==0) {
    return -1;
  }
  
  // if only source, separate the module name
  if (i==1) {
    p=StrRChr (tx->src, NULL, '\\');
    if (p!=NULL) {
      strncpy (tx->dst, p+1, MAX_PATH);
    } else {
      strncpy (tx->dst, tx->src, MAX_PATH);
    }
  }
  return mode;
}

/**F*****************************************************************/
int s_put (spp_ctx *c, char *path)
/**
 * PURPOSE : open and send local file to client
 *
 * RETURN :  
 *
 * NOTES :   
 *
 *F*/
{
  HANDLE   in;
  spp_blk  out;
  spp_tx   tx;
  int      r, eof, complete;
  uint64_t len, total=0;
  
  // split path into source and destination
  parse_path (path, &tx);
  
  // open source file for reading
  in=CreateFile (tx.src, GENERIC_READ, FILE_SHARE_READ, 
    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  
  // opened okay?
  if (in != INVALID_HANDLE_VALUE)
  {
    // tell client we want to send a file
    out.len.w        = strlen(tx.dst) + sizeof(int);
    out.data.cmd.opt = SPP_CMD_PUT;
    // copy destination file name to buffer
    strncpy (out.data.cmd.buf, tx.dst, MAX_PATH-1);
    // send command
    r=spp_send(c, &out);
    // now wait for the error code
    r=spp_recv(c, &out);
    // file created remotely okay?
    if (r==SPP_ERR_OK && out.data.fx.err==ERROR_SUCCESS)
    {
      printf ("[ uploading \"%s\" to \"%s\"\n", 
        tx.src, tx.dst);
      // while reading
      GetFileSizeEx (in, (PLARGE_INTEGER)&total);
      
      for (len=0;;) 
      {  
        ReadFile (in, out.data.b, SPP_DATA_LEN, &out.len.w, 0);
        
        // after spp_send, out.len will be encrypted
        if (out.len.w == 0) {
          complete = 1;
          eof      = 1;
        }
        
        len += out.len.w;
        
        // send data
        if ((r=spp_send(c, &out)) != SPP_ERR_OK) break;
        
        printf ("\r[ sent %llu of %llu bytes - %I64u%% complete",
            len, total, (len * 100) / total);
            
        // end of file?
        if (eof) break;
      }
      if (complete) printf("\n[ upload completed.\n");
    } else {
      SetLastError(out.data.fx.err);
      xstrerror("REMOTE: CreateFile(\"%s\")", tx.dst);
    }
    CloseHandle (in);
  } else {
    xstrerror("CreateFile(\"%s\")", tx.src);
  }
  return r;
}

/**F*****************************************************************/
int s_get (spp_ctx *c, char *path)
/**
 * PURPOSE : receive a file from client system
 *
 * RETURN :  spp error code
 *
 * NOTES :   None
 *
 *F*/
{
  HANDLE   out;
  uint32_t wn;
  spp_blk  in;
  spp_tx   tx;
  int      r, complete=0;
  uint64_t len, total, pct;
  
  // split path in source and destination
  parse_path (path, &tx);
  
  DEBUG_PRINT("creating %s", tx.dst);
  // first, create a file locally for write access
  out=CreateFile (tx.dst, GENERIC_WRITE, 0, NULL, 
    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    
  // if file created locally
  if (out!=INVALID_HANDLE_VALUE)
  {
    DEBUG_PRINT("will open %s on remote system", tx.src);
    // tell client we want to download a file
    in.len.w        = strlen(tx.src) + sizeof(int);
    in.data.cmd.opt = SPP_CMD_GET;
    // copy source path
    strncpy (in.data.cmd.buf, tx.src, MAX_PATH-1);
    DEBUG_PRINT("sending request");
    r=spp_send(c, &in);
    // now wait for error code to determine if available.
    DEBUG_PRINT("waiting for response");
    r=spp_recv(c, &in);
    // send was okay and error code is good?
    if (r==SPP_ERR_OK && in.data.fx.err==ERROR_SUCCESS)
    {
      // size of file will come after error code
      DEBUG_PRINT("receiving file");
      printf ("[ downloading \"%s\" to \"%s\"\n", 
        tx.src, tx.dst);
      total = in.data.fx.size;
      // start looping until we receive in.len==0
      for (len=0;;) 
      {
        // receive data
        if ((r=spp_recv(c, &in)) != SPP_ERR_OK) { 
          DEBUG_PRINT("spp_recv error");
          break;
        }
        // zero length indicates end of transmission
        if (in.len.w == 0) {
          DEBUG_PRINT("EOF received");
          complete=1;
          break;
        }
        // write to file
        DEBUG_PRINT("writing %i bytes to file", in.len.w);
        WriteFile (out, in.data.b, in.len.w, &wn, 0);
        len += wn;
        pct = (len * 100) / total;
        printf ("\r[ received %llu of %llu bytes - %llu%% complete", 
          len, total, pct);
      }
      if (complete) printf ("\n[ download completed.\n");
      DEBUG_PRINT("received file");
    } else {
      // file wasn't available, set error code
      SetLastError(in.data.fx.err);
      xstrerror ("REMOTE: CreateFile(\"%s\")", tx.src);
    }
    GetFileSizeEx(out, (PLARGE_INTEGER)&total);
    // close handle
    CloseHandle (out);
    if (total==0) {
      printf ("%s is empty..deleting", tx.dst);
      DeleteFile(tx.dst);
    }
  } else {
    xstrerror ("CreateFile(\"%s\")", tx.dst);
  }
  return r;
}

/**F*****************************************************************/
static uint32_t WINAPI stdin_thread (void *param)
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
      SPP_DATA_LEN, &input.len, NULL);
      
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
  int              opt;
  
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

/**F*****************************************************************/
uint32_t session (spp_ctx *c)
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
  uint32_t   e, wn, i, cmd_mode=0, terminate=0, end=0;
  spp_blk in, out;
  HANDLE  evt[MAXIMUM_WAIT_OBJECTS];
  uint32_t   stdin_evt=0, sck_evt=0, evt_cnt=0;
  
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
  hThread=CreateThread (NULL, 0, stdin_thread, NULL, 0, NULL);
            
  // keep going until disconnection of client/user exits
  printf ("[ ready\n");
  
  do {
    if (!cmd_mode) printf (">");
    DEBUG_PRINT("waiting for events");
    // wait for events
    e=wait_evt(evt, evt_cnt, sck_evt, c->s);
    
    // failure? break
    if (e==-1) {
      xstrerror("wait error");
      printf ("[ wait_evt() failure : returned %08X\n", e);
      break;
    }
    
    // read from socket?
    if (e==sck_evt) 
    {
      DEBUG_PRINT("reading from socket");
      // receive packet, break on error
      if (spp_recv (c, &in) != SPP_ERR_OK) {
        DEBUG_PRINT("[ spp_recv() error\n");
        break;
      }
      // if we're interactive with remote cmd.exe and in.len is zero
      // cmd.exe has ended so set cmd_mode to zero and continue
      if (cmd_mode == 1 && in.len.w == 0) {
        DEBUG_PRINT("cmd.exe terminated");
        cmd_mode=0;
        continue;
      } else if (cmd_mode==1) {
        // else we're still interactive, write to console
        WriteConsole (stdoutput, in.data.b, in.len.w, &wn, 0);
      } else {
        // this might happen for file transfers
        // but since we're no longer in s_put or s_get
        // this shouldn't happen so break
        printf ("[ error : received %i bytes", in.len);
        break;
      }
    } else 
    
    // user input?
    if (e==stdin_evt) 
    {
      // if we're not in cmd_mode, try parse command
      if (!cmd_mode) 
      {
        // command is 4 bytes
        in.len.w        = sizeof(uint32_t);
        in.data.cmd.opt = ~0UL;
        // loop through available commands
        for (i=0; i<sizeof (cmds) / sizeof (spp_opt); i++) {
          if (strncmp (input.buf, cmds[i].s, strlen (cmds[i].s)) == 0) {
            in.data.cmd.opt = cmds[i].cmd;
            break;
          }
        }
        // do we have valid command?
        switch (in.data.cmd.opt) 
        {
          case SPP_CMD_HELP: {
            printf ("\n  valid commands\n");
            printf ("\n  exit                 - terminate remote code");
            printf ("\n  ls                   - list local directory");
            printf ("\n  cmd                  - execute cmd.exe");
            printf ("\n  put <local> <remote> - upload file");
            printf ("\n  get <remote> <local> - download file\n");
            break;
          }
          // terminate client?
          case SPP_CMD_TERM:
            terminate=1;
            spp_send(c, &in);
            break;
          // execute cmd.exe?
          case SPP_CMD_SHELL: {
            cmd_mode=1;
            spp_send(c, &in);
            break;
          }
          // upload a file?
          case SPP_CMD_PUT: {
            DEBUG_PRINT("user upload cmd: %s", input.buf);
            s_put (c, input.buf);
            break;
          }
          // download a file?
          case SPP_CMD_GET: {
            DEBUG_PRINT("user download cmd: %s", input.buf);
            s_get (c, input.buf);
            break;
          }
          case SPP_CMD_LIST: {
            system("dir");
            break;
          }
          // invalid command
          default:
            printf ("[ unrecognised command\n");
            break;
        }
      } else {
        // we're in cmd_mode, copy input to packet buffer
        out.len.w = input.len;
        memcpy (out.data.b, input.buf, input.len);
        // send to cmd.exe on client
        spp_send(c, &out);
      }
      // start reading user input again
      SetEvent (input.evtbck);
    }
  } while (!end && !terminate);
  
  printf ("[ cleaning up\n");
  
  CloseHandle (hThread);
  CloseHandle (input.evtbck);
  CloseHandle (evt[stdin_evt]);
  evt_cnt--;
  
  return terminate;
}

void server(args_t *p)
{
  spp_ctx c;
  int     t;
  
  printf ("[ initializing SPP with %i-bit RSA key...", SPP_RSA_LEN);
  if (!spp_init(&c)) {
    printf ("spp_init failed");
    xstrerror("spp_init");
    return;
  }
  
  printf ("done\n");
  
  // bind to local address
  printf ("[ binding to %s\n", addr2ip(p));
  if (bind (p->s, p->ai_addr, p->ai_addrlen) != SOCKET_ERROR) 
  {
    // listen for incoming connections
    printf ("[ listening for connections\n");
    if (listen (p->s, SOMAXCONN) != SOCKET_ERROR) 
    {
      printf ("[ waiting for connections on %s\n", addr2ip(p));
      p->r=accept (p->s, p->ai_addr, &p->ai_addrlen);
      
      if (p->r!=SOCKET_ERROR) {
        printf ("[ connection from %s\n", addr2ip(p));
        printf ("[ performing key exchange\n");
        c.s=p->r;
        if (spp_handshake(&c))
        {
          session(&c);
          printf ("[ closing connection\n");
        }
      } else {
        xstrerror ("accept()");
      }       
    } else {
      xstrerror ("listen()");
    }
  } else {
    xstrerror ("bind()");
  }
  spp_end(&c);
}
