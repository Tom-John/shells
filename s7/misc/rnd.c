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
  
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if defined(__Linux__)
#define NIX
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#elif defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32")
#endif

void bin2hex(const char *s, uint8_t x[], int len) {
    int i;
    printf ("\n // %s", s);
    for (i=0; i<len; i++) {
      if ((i & 7)==0) putchar('\n');
      printf (" 0x%02x,", x[i]);
    }
    putchar('\n');
}

#ifdef NIX
int randomx(void *out, size_t outlen);

int random(void *out, size_t outlen)
{
    int     fd;
    ssize_t u=0, len;
    uint8_t *p=(uint8_t*)out;
    
    fd = open("/dev/urandom", O_RDONLY);
    
    if (fd >= 0) {
      for (u=0; u<outlen;) {
        len = read(fd, p + u, outlen - u);
        if (len<0) break;        
        u += (size_t)len;
      }
      close(fd);
    }
    return u==outlen;
}

#else
  
int random(void *out, size_t outlen)
{
    HCRYPTPROV hp;
    BOOL       r=FALSE;
      
    if (CryptAcquireContext(&hp, 0, 0, PROV_RSA_FULL,
      CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
      r = CryptGenRandom(hp, outlen, out);
      CryptReleaseContext(hp, 0);
    }
    return r;
}

#endif

int main(void) {
  
  uint8_t rnd[64];
  
  randomx(rnd, sizeof(rnd)); 
  bin2hex("random", rnd, sizeof(rnd));
  
  return 0;
}
