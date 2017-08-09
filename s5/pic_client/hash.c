
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3.h"

// generate sha3-256 hash of dll and api
uint32_t api_hash(char dll[], char api[])
{ 
  union {
    uint8_t  b[32];
    uint32_t w[8];
  } h;
  
  SHA3_CTX ctx;
  int      i;
  char     c;
  uint8_t  f[64+1]; 
  uint32_t s = 0x9e3779b9UL; // change to something unique
    
  SHA3_Init(&ctx, SHA3_256);         // create 256-bit hash
  SHA3_Update(&ctx, &s, sizeof(s));  // unique secret

  // copy dll converted to lowercase
  for (i=0; dll[i] != 0 && i<sizeof(f)-1; i++) {
    f[i] = (dll[i] | 0x20);
  }
  f[i] = 0;
  SHA3_Update(&ctx, f, i);
  SHA3_Update(&ctx, api, strlen(api));
  SHA3_Final(h.b, &ctx);
  
  // only return the first 32-bits
  return h.w[0];
}


int main(int argc, char *argv[])
{
  char api[260];
  FILE *fd;
  int  idx=0;
  char *p;
  
  if (argc<2) {
    printf ("\n  usage: api_hash <file> <dll>\n");
    return 0;
  }
  
  fd=fopen(argv[1], "rb");
  if (fd!=NULL) {
    while (!feof(fd)) {
      fgets (api, sizeof(api)-1, fd);
      
      p=strchr(api, '\n');
      if (p!=NULL) *p=0;
      
      p=strchr(api, '\r');
      if (p!=NULL) *p=0;
      
      if ((idx++ & 3)==0) putchar('\n');
      printf ("0x%08X, ", api_hash(argv[2], api));
    }
    fclose(fd);
  }
  return 0;
}
