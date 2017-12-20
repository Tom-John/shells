
// test unit for mx.asm
// requires GMP

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <gmp.h>

char OAKLEY_PRIME_MODP768[]=
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";
  
char OAKLEY_PRIME_MODP1024[]=
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF";
    
char OAKLEY_PRIME_MODP2048[]=
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
      
#define BN_LEN 1024  // should be enough for 8192-bits

// just to test modexp asm function
typedef struct _dh_t {
    uint32_t maxbits;
    uint32_t maxbytes;
    
    // p + g group parameters
    uint8_t p[BN_LEN];
    uint8_t g[BN_LEN];
    
    // private keys
    uint8_t x[BN_LEN];
    uint8_t y[BN_LEN];
    
    // public keys
    uint8_t A[BN_LEN];
    uint8_t B[BN_LEN];
    
    // session keys
    uint8_t s1[BN_LEN];
    uint8_t s2[BN_LEN];
  
} DH_T;

// b=base, e=exponent, m=modulus, r=result
void modexp (uint32_t maxbits, void *b, void *e, void *m, void *r);

void dump_bn (char txt[], void *buf, int len)
{
    int i;
    
    printf ("%s", txt);
    
    for (i=len-1; i>=0; i--) {
      printf ("%02x", ((uint8_t*)buf)[i]);
    }
}

void bin2hex(const char *s, uint8_t x[], int len) {
    int i;
    printf ("\n // %s", s);
    for (i=0; i<len; i++) {
      if ((i & 7)==0) putchar('\n');
      printf (" 0x%02x,", x[i]);
    }
    putchar('\n');
}
/**
#if defined(__Linux__)
#define NIX
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#elif defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32")
#endif

#ifdef NIX
int randomx(void *out, size_t outlen);

int random(void *out, size_t outlen)
{
    int     fd;
    ssize_t  u=0, len;
    uint8_t *p=(uint8_t*)out;
    
    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
      for (u=0; u<outlen;) {
        len = read(fd, p + u, outlen - u);
        if (len<0) break;        
        u += (size_t)len;
      }
      close(fd);
    }
    return u==outlen;
}

#else
  
int random(void *out, size_t outlen)
{
    HCRYPTPROV hp;
    BOOL       r=FALSE;
      
    if (CryptAcquireContext(&hp, 0, 0, PROV_RSA_FULL,
      CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
      r = CryptGenRandom(hp, outlen, out);
      CryptReleaseContext(hp, 0);
    }
    return r;
}

#endif*/

void dh_asm (uint32_t numlen, void *p, void *g, void *x, void *y)
{
    DH_T dh;
    uint32_t len=numlen>>3;
    
    // zero init
    memset (&dh, 0, sizeof (dh));
    
    dh.maxbits=(numlen&-32)+32;
    dh.maxbytes=dh.maxbits>>3;
    
    // group parameters
    memcpy (dh.p, p, len);
    memcpy (dh.g, g, 1);     // this is presumed to be number 2
    
    // then private keys
    memcpy (dh.x, x, len);
    memcpy (dh.y, y, len);
   
    // Alice obtains A = g ^ x mod p
    modexp (dh.maxbytes, dh.g, dh.x, dh.p, dh.A);

    // Bob obtains B = g ^ y mod p
    modexp (dh.maxbytes, dh.g, dh.y, dh.p, dh.B);

    // *************************************
    // Bob and Alice exchange A and B values
    // *************************************
    
    // Alice computes s1 = B ^ x mod p
    modexp (dh.maxbytes, dh.B, dh.x, dh.p, dh.s1);
    
    // Bob computes   s2 = A ^ y mod p
    modexp (dh.maxbytes, dh.A, dh.y, dh.p, dh.s2);
    
    // s1 + s2 should be equal
    if (memcmp (dh.s1, dh.s2, len)==0) {
      printf ("\n\nx86 asm Key exchange succeeded");
      dump_bn ("\n\nx86 Session key = ", dh.s1, len);
      putchar('\n');
    } else {
      printf ("\nx86 Key exchange failed\n");
  }
}

char *mpz_hex(mpz_t x)
{
    static char r[1024];
    
    mpz_get_str(r, 16, x);
    return r;
}

void dh (char modp[])
{
    mpz_t           p, g, x, y, A, B, s1, s2;
    uint32_t        maxbits;
    uint8_t         px[256], gx[256], xx[256], yx[256];
    gmp_randstate_t state;
    
    memset(px, 0, sizeof(px));
    memset(gx, 0, sizeof(gx));
    memset(xx, 0, sizeof(xx));
    memset(yx, 0, sizeof(yx));
    
    gmp_randinit_default(state);
    
    mpz_init(p);  mpz_init(g); 
    mpz_init(x);  mpz_init(y);
    mpz_init(A);  mpz_init(B);
    mpz_init(s1); mpz_init(s2);

    mpz_set_str (p, modp, 16);
    mpz_set_str (g, "2", 16);
    
    // generate 2 random integers in range of p
    mpz_urandomb(x, state, 32);
    mpz_urandomb(y, state, 32);
    
    puts ("\n\n***********************************\n");
    printf ("P is %i-bits\n", mpz_sizeinbase(p, 2));
    
    printf ("p = %s\n", mpz_hex (p));
    printf ("g = %s\n", mpz_hex (g));
    printf ("x = %s\n", mpz_hex (x));
    printf ("y = %s\n", mpz_hex (y));
    
    // Alice does g ^ x mod p
    mpz_powm (A, g, x, p);

    printf ("A = %s\n", mpz_hex (A));
    
    // Bob does g ^ y mod p
    mpz_powm (B, g, y, p);

    printf ("B = %s\n", mpz_hex (B));
    
    // *************************************
    // Bob and Alice exchange A and B values
    // *************************************
    
    // Alice computes session key
    mpz_powm (s1, B, x, p);

    printf ("s1 = %s\n", mpz_hex (s1));
    
    // Bob computes session key
    mpz_powm (s2, A, y, p);
    
    printf ("s2 = %s\n", mpz_hex (s2));
    
    // check if both keys match
    if (mpz_cmp (s1, s2) == 0) {
      printf ("\n\nKey exchange succeeded");
      printf ("\n\nSession key = %s\n", mpz_hex (s1));
    } else {
      printf ("\n\nKey exchange failed\n");
    }
    
    mpz_export(px, NULL, -1, 1, 0, 0, p);
    mpz_export(gx, NULL, -1, 1, 0, 0, g);
    mpz_export(xx, NULL, -1, 1, 0, 0, x);
    mpz_export(yx, NULL, -1, 1, 0, 0, y);
    
    bin2hex("p", px, mpz_sizeinbase(p, 2)/8);
    
    // call the assembler function
    dh_asm (mpz_sizeinbase(p, 2), px, gx, xx, yx);

    mpz_clear (s2);
    mpz_clear (s1);
    mpz_clear (p);
    mpz_clear (g);
    mpz_clear (y);
    mpz_clear (x);
    mpz_clear (B);
    mpz_clear (A);
}

int main (int argc, char *argv[]) 
{
    dh (OAKLEY_PRIME_MODP768);
    dh (OAKLEY_PRIME_MODP1024);  
    dh (OAKLEY_PRIME_MODP2048);  
    return 0;
}
