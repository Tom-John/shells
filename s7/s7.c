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
/**F*****************************************************************/
void xstrerror (char *fmt, ...) 
/**
 * PURPOSE : Display windows error
 *
 * RETURN :  Nothing
 *
 * NOTES :   None
 *
 *F*/
{
    char    *error=NULL;
    va_list arglist;
    char    buffer[2048];
    DWORD   dwError=GetLastError();
    
    va_start (arglist, fmt);
    wvnsprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
        (LPSTR)&error, 0, NULL))
    {
      printf ("[ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      printf ("[ %s : %lu\n", buffer, dwError);
    }
}
#else
void xstrerror(char *fmt, ...)
{
    char    buffer[2048];
    va_list arglist;

    va_start (arglist, fmt);
    vsnprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
    va_end (arglist);
    
    printf ("[ %s : %s\n", buffer, strerror(errno));  
}
#endif

char *addr2ip(args_t *p)
{
#ifdef WIN
    DWORD ip_size=INET6_ADDRSTRLEN;
    WSAAddressToString (p->ai_addr, p->ai_addrlen, 
      NULL, (char*)p->ip, &ip_size);
#else
    void *src;

    if (p->ai_family==AF_INET) {
      src=(void*)&p->v4.sin_addr;
    } else {
      src=(void*)&p->v6.sin6_addr;
    }
    inet_ntop(p->ai_family, src, p->ip, INET6_ADDRSTRLEN);
#endif
    return p->ip;
}

int init_network (args_t *p)
/**
 * PURPOSE : initialize winsock for windows, resolve network address
 *
 * RETURN :  1 for okay else 0
 *
 * NOTES :   None
 *
 *F*/
{
    struct addrinfo *list=NULL, *e=NULL;
    struct addrinfo hints;
    int             t;
    
    // initialize winsock if windows
#ifdef WIN
    WSADATA wsa;
    WSAStartup (MAKEWORD (2, 0), &wsa);
#endif

    // set network address length to zero
    p->ai_addrlen = 0;
    
    // if no address supplied
    if (p->address==NULL)
    {
      // is it ipv4?
      if (p->ai_family==AF_INET) {
        p->v4.sin_family      = AF_INET; 
        p->v4.sin_port        = htons((u_short)p->port_nbr);
        p->v4.sin_addr.s_addr = INADDR_ANY;
        p->ai_addr            = (struct sockaddr*)&p->v4;
        p->ai_addrlen         = sizeof (struct sockaddr_in);
      } else {
        // else it's ipv6
        p->v6.sin6_family     = AF_INET6;
        p->v6.sin6_port       = htons((u_short)p->port_nbr);
        p->v6.sin6_addr       = in6addr_any;
        p->ai_addr            = (struct sockaddr*)&p->v6;
        p->ai_addrlen         = sizeof (struct sockaddr_in6);
      }
    } else {
      memset (&hints, 0, sizeof (hints));

      hints.ai_flags    = AI_PASSIVE;
      hints.ai_family   = p->ai_family;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;    
      
      // get all network addresses
      printf ("[ resolving network address...\n");
      t=getaddrinfo (p->address, p->port, &hints, &list);
      if (t == 0) 
      {
        for (e=list; e!=NULL; e=e->ai_next) 
        {
          // copy to ipv4 structure
          if (p->ai_family==AF_INET) {
            memcpy (&p->v4, e->ai_addr, e->ai_addrlen);
            p->ai_addr     = (struct sockaddr*)&p->v4;        
          } else {
            // ipv6 structure
            memcpy (&p->v6, e->ai_addr, e->ai_addrlen);
            p->ai_addr     = (struct sockaddr*)&p->v6;
          }
          // assign size of structure
          p->ai_addrlen = e->ai_addrlen;
          break;
        }
        freeaddrinfo (list);
      } else {
        xstrerror ("getaddrinfo");
      }
    }
    // create socket if we have address resolved
    if (p->ai_addrlen != 0) 
    {
      #ifdef WIN
      p->s=WSASocket(p->ai_family, SOCK_STREAM, IPPROTO_IP, NULL, 0, 0);
      #else
      p->s=socket(p->ai_family, SOCK_STREAM, IPPROTO_IP);
      #endif
      if (p->s != ~0UL) 
      {
        // this is only really necessary for listen operations
        t=1;
        setsockopt (p->s, SOL_SOCKET, SO_REUSEADDR, (char*)&t, sizeof (t));
      } else {
        p->ai_addrlen=0;
      }
    }
    return p->ai_addrlen;
}
/**F*****************************************************************/
void usage (void) 
{
    printf ("\n  usage: s7 <address> [options]\n");
    printf ("\n  -4           Use IP version 4 (default)");
    printf ("\n  -6           Use IP version 6");
    printf ("\n  -p <number>  Port number to use (default is %i)", 
        DEFAULT_PORT);
    exit (0);
}

/**F*****************************************************************/
char* getparam (int argc, char *argv[], int *i)
{
    int n=*i;
    if (argv[n][2] != 0) {
      return &argv[n][2];
    }
    if ((n+1) < argc) {
      *i=n+1;
      return argv[n+1];
    }
    printf ("[ %c%c requires parameter\n", argv[n][0], argv[n][1]);
    exit (0);
}

void parse_args (args_t *p, int argc, char *argv[])
{
    int  i;
    char opt;
    
    // for each argument
    for (i=1; i<argc; i++)
    {
      // is this option?
      if (argv[i][0]=='-' || argv[i][1]=='/')
      {
        // get option value
        opt=argv[i][1];
        switch (opt)
        {
          case '4':
            p->ai_family=AF_INET;
            break;
          case '6':     // use ipv6 (default is ipv4)
            p->ai_family=AF_INET6;
            break;
          case 'l':
            p->mode = SERVER_MODE; 
            break;          
          case 'p':     // port number
            p->port=getparam(argc, argv, &i);
            p->port_nbr=atoi(p->port);
            break;
          case '?':     // display usage
          case 'h':
            usage ();
            break;
          default:
            printf ("  [ unknown option %c\n", opt);
            break;
        }
      } else {
        // assume it's hostname or ip
        p->address = argv[i];
        p->mode    = CLIENT_MODE;
      }
    }
}

int main (int argc, char *argv[])
{
    args_t args;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    memset (&args, 0, sizeof(args));
    
    // set default parameters
    args.address   = NULL;
    args.ai_family = AF_INET;
    args.port_nbr  = DEFAULT_PORT;
    args.mode      = SERVER_MODE;
    
    printf ("\n[ Server/Client for encrypted PIC v0.1\n");
    
    parse_args(&args, argc, argv);
    
    if (init_network(&args))
    {
      if (args.mode == CLIENT_MODE) {
        client(&args);
      } else {
        server(&args);
      }
      shutdown (args.s, SHUT_RDWR);
      close(args.s);
    }
    return 0;
}
