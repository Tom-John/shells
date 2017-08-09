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

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <winnt.h>
#include <wincrypt.h>
//#include <winternl.h>
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

#include "aes.h"
#include "sha3.h"
#include "modexp.h"

typedef void *PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  BYTE                          Reserved4[104];
  PVOID                         Reserved5[52];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved6[128];
  PVOID                         Reserved7[1];
  ULONG                         SessionId;
} PEB, *PPEB;

typedef struct _MY_PEB_LDR_DATA {
  ULONG      Length;
  BOOL       Initialized;
  PVOID      SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
  LIST_ENTRY     InLoadOrderLinks;
  LIST_ENTRY     InMemoryOrderLinks;
  LIST_ENTRY     InInitializationOrderLinks;
  PVOID          DllBase;
  PVOID          EntryPoint;
  ULONG          SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef BOOL (WINAPI* GetFileSizeEx_t)(
    HANDLE         hFile,
   PLARGE_INTEGER lpFileSize);

typedef BOOL (WINAPI* Wow64DisableWow64FsRedirection_t)(
           PVOID *OldValue);
    
typedef BOOL (WINAPI* CryptAcquireContextA_t) (
           HCRYPTPROV  *phProv,
        LPCSTR    szContainer,
        LPCSTR    szProvider,
            DWORD       dwProvType,
            DWORD       dwFlags);
    
typedef BOOL (WINAPI* CryptReleaseContext_t) (
        HCRYPTPROV  hProv,
        DWORD       dwFlags);
    
typedef BOOL (WINAPI* CryptGenRandom_t) (
                        HCRYPTPROV  hProv,
                        DWORD   dwLen,
    BYTE    *pbBuffer);
    
typedef HMODULE (WINAPI* LoadLibrary_t)(
   LPCTSTR lpFileName
);

typedef int (WINAPI* WSACleanup_t)(void);

typedef DWORD (WINAPI* GetTickCount_t)(void);
typedef DWORD (WINAPI* GetLastError_t)(void);
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
