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

#include "clib.h"

size_t strlen(const char *s) {
  size_t n=0;
  
  while (*s++ != 0) {
    n++;
  }
  return n;
}

void *memcpy (void *destination, const void* source, size_t num)
{
  size_t i;
  uint8_t *s=(char*)source, *d=(uint8_t*)destination;
  
  for (i=0; i<num; i++) {
    d[i] = s[i];
	}
  return destination;
}

void *memset (void *ptr, int value, size_t num)
{
  size_t  i;
  uint8_t *p=(uint8_t*)ptr;
  
  for (i=0; i<num; i++) {
    p[i] = value;
	}
  return ptr;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
  uint8_t u1, u2;
	uint8_t *p1, *p2;

	p1=(uint8_t*)s1;
	p2=(uint8_t*)s2;
	
  for ( ; n-- ; p1++, p2++) {
	  u1 = *p1;
	  u2 = *p2;
	  
		if (u1 != u2) {
	    return (u1 - u2);
	  }
  }
  return 0;
}

int tolower(int c) {
  return (c >= 'A' && c <= 'Z') ? c | 0x20 : c;  
}

int toupper(int c) {
  return (c >= 'a' && c <= 'z') ? c - 0x20 : c;  
}

// case insensitive string compare
int strcmpi(const char *s1, const char *s2) {
  uint8_t u1, u2;
	uint8_t *p1, *p2;
  size_t  n;
  
  n = strlen(s1);
  
	p1=(uint8_t*)s1;
	p2=(uint8_t*)s2;
	
  for ( ; n-- ; p1++, p2++) {
	  u1 = tolower(*p1);
	  u2 = tolower(*p2);
	  
		if (u1 != u2) {
	    return (u1 - u2);
	  }
  }
  return 0;
}
