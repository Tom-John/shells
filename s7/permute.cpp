#include <stdio.h>
#include <Windows.h>

#include "macros.h"

void bin2hex(const char *s, uint8_t x[], int len) {
    int i;
    printf ("\n // %s", s);
    for (i=0; i<len; i++) {
      if ((i & 7)==0) putchar('\n');
      printf (" 0x%02x,", x[i]);
    }
    putchar('\n');
}

// round constant function
// Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1
uint32_t rc (uint8_t *LFSR) {
    uint32_t c; 
    int8_t   t;
    uint8_t  i;

    c = 0;
    t = *LFSR;
    
    for (i=1; i<128; i += i) 
    {
      if (t & 1) {
        // if shift value is < 32
        if ((i-1) < 32) {
          c ^= 1UL << (i - 1);
        }
      }
      t = (t & 0x80) ? (t << 1) ^ 0x71 : t << 1;
    }
    *LFSR = (uint8_t)t;
    return c;
}

void keccak(void *state) {
    uint32_t i, j, rnd;
    uint32_t t, u, bc[5];
    uint8_t  r, lfsr=1;
    uint32_t *st=(uint32_t*)state;
  
    uint8_t p[24] = 
    { 10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 
      15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1  };
      
    uint8_t m[9] = 
    { 0, 1, 2, 3, 4, 0, 1, 2, 3};
  
    for (rnd=0; rnd<22; rnd++) {
      // Theta
      for (i=0; i<5; i++) {
        t  = st[i   ];
        t ^= st[i+ 5];      
        t ^= st[i+10];      
        t ^= st[i+15];      
        t ^= st[i+20];
        bc[i] = t;
      }
      for (i=0; i<5; i++) {
        t  = bc[m[(i + 4)]]; 
        t ^= ROTL32(bc[m[(i + 1)]], 1);
        for (j=i; j<25; j+=5) {
          st[j] ^= t;
        }
      }
      // Rho + Pi
      u = st[1];
      for (i=0, r=0; i<24; i++) {
        r += i + 1;
        u  = ROTL32(u, r & 31);
        XCHG(st[p[i]], u);
        bc[0] = u;
      }
      // Chi
      for (i=0; i<25; i+=5) {
        memcpy(&bc, &st[i], 5*4);
        for (j=0; j<5; j++) {
          t  = ~bc[m[(j + 1)]];
          t &=  bc[m[(j + 2)]];
          st[j + i] ^= t;
        }
      }
      // Iota
      st[0] ^= rc(&lfsr);
    }
}

void chacha(void *state)
{
    int         i;
    uint32_t    a, b, c, d, r, t, idx;
    uint32_t    *s=(uint32_t*)state;
    
    uint16_t idx16[8]=
    { 0xC840, 0xD951, 0xEA62, 0xFB73,    // column index
      0xFA50, 0xCB61, 0xD872, 0xE943 };  // diagnonal index
    
    for (i=0; i<8; i++) {
      idx = idx16[i];
        
      a = (idx         & 0xF);
      b = ((idx >>  4) & 0xF);
      c = ((idx >>  8) & 0xF);
      d = ((idx >> 12) & 0xF);
  
      r = 0x07080C10;
      
      /* The quarter-round */
      do {
        s[a]+= s[b]; 
        s[d] = ROTL32(s[d] ^ s[a], r & 0xFF);
        XCHG(c, a);
        XCHG(d, b);
        r >>= 8;
      } while (r != 0);
    }    
}

// The non-linear primitive
#define H(A, B) ( ( (A) ^ (B) ) ^ ( ( (A) & (B) ) << 1) )

void norx(void *state)
{
    int         i;
    uint32_t    a, b, c, d, r, t, idx;
    uint32_t    *s=(uint32_t*)state;
    
    uint16_t idx16[8]=
    { 0xC840, 0xD951, 0xEA62, 0xFB73,    // column index
      0xFA50, 0xCB61, 0xD872, 0xE943 };  // diagnonal index
    
    for (i=0; i<8; i++) {
      idx = idx16[i];
        
      a = (idx         & 0xF);
      b = ((idx >>  4) & 0xF);
      c = ((idx >>  8) & 0xF);
      d = ((idx >> 12) & 0xF);
  
      r = 0x1F100B08; // rotation offsets
      
      // The quarter-round
      do {
        s[a] = H(s[a], s[b]); 
        s[d] = ROTR32(s[d] ^ s[a], r & 0xFF);
        XCHG(c, a);
        XCHG(d, b);
        r >>= 8;
      } while (r != 0);
    }    
}

void cube(void *state)
{
    int      i, j, k;
    uint32_t y[16];
    uint32_t *s=(uint32_t*)state;

    for (k=7, j=8; j>0; k+=4, j-=4)
    {
      for (i=0; i<16; ++i) s[i + 16] += s[i];
      for (i=0; i<16; ++i) y[i ^ j] = s[i];
      for (i=0; i<16; ++i) s[i] = ROTL32(y[i], k);
      for (i=0; i<16; ++i) s[i] ^= s[i + 16];
      for (i=0; i<16; ++i) y[i ^ (j>>2)] = s[i + 16];
      for (i=0; i<16; ++i) s[i + 16] = y[i];
    }
}

void chaskey(void *state) {
  uint32_t *s=(uint32_t*)state;

    s[0] += s[1]; 
    s[1]=ROTL32(s[1], 5); 
    s[1] ^= s[0]; 
    s[0]=ROTL32(s[0],16); 
    s[2] += s[3]; 
    s[3]=ROTL32(s[3], 8); 
    s[3] ^= s[2]; 
    s[0] += s[3]; 
    s[3]=ROTL32(s[3],13); 
    s[3] ^= s[0]; 
    s[2] += s[1]; 
    s[1]=ROTL32(s[1], 7); 
    s[1] ^= s[2]; 
    s[2]=ROTL32(s[2],16); 
}

void gimli(void *state)
{
  int      r, j;
  uint32_t t, x, y, z;
  uint32_t *s=(uint32_t*)state;
  
  for (r=0x9e377918; r!=0x9e377900; r--) {
    // apply SP-box
    for (j=0; j<4; j++) {
      x = ROTR32(s[    j], 8);
      y = ROTL32(s[4 + j], 9);
      z =        s[8 + j];

      s[8 + j] = x ^ (z << 1) ^ ((y & z) << 2);
      s[4 + j] = y ^ x        ^ ((x | z) << 1);
      s[j]     = z ^ y        ^ ((x & y) << 3);
    }

    // apply Linear layer
    t = r & 3;
    
    // small swap
    if (t == 0) {
      XCHG(s[0], s[1]);
      XCHG(s[2], s[3]);
      
      // add constant      
      s[0] ^= r;
    }   
    // big swap
    if (t == 2) {
      XCHG(s[0], s[2]);
      XCHG(s[1], s[3]);
    }
  }
}

void ascon(void *state) {
    int      i;
    uint64_t x0, x1, x2, x3, x4;
    uint64_t t0, t1, t2, t3, t4;
    
    uint64_t *x=(uint64_t*)state;
    
    // load 320-bit state
    x0 = x[0]; x1 = x[1];
    x2 = x[2]; x3 = x[3];
    x4 = x[4];

    for (i=0; i<6; i++) {
      // addition of round constant
      x2 ^= ((0xFULL - i) << 4) | i;

      // substitution layer
      x0 ^= x4;    x4 ^= x3;    x2 ^= x1;
      t0  = x0;    t1  = x1;    t2  = x2;    t3  =  x3;    t4  = x4;
      t0  = ~t0;   t1  = ~t1;   t2  = ~t2;   t3  = ~t3;    t4  = ~t4;
      t0 &= x1;    t1 &= x2;    t2 &= x3;    t3 &=  x4;    t4 &= x0;
      x0 ^= t1;    x1 ^= t2;    x2 ^= t3;    x3 ^=  t4;    x4 ^= t0;
      x1 ^= x0;    x0 ^= x4;    x3 ^= x2;    x2  = ~x2;

      // linear diffusion layer
      x0 ^= ROTR64(x0, 19) ^ ROTR64(x0, 28);
      x1 ^= ROTR64(x1, 61) ^ ROTR64(x1, 39);
      x2 ^= ROTR64(x2,  1) ^ ROTR64(x2,  6);
      x3 ^= ROTR64(x3, 10) ^ ROTR64(x3, 17);
      x4 ^= ROTR64(x4,  7) ^ ROTR64(x4, 41);

    }
    // save 320-bit state
    x[0] = x0; x[1] = x1;
    x[2] = x2; x[3] = x3;
    x[4] = x4;
}

int main()
{
  int     i, idx;
  uint8_t *p=(uint8_t*)0x7FFE0000;
  uint8_t state[128];
	
  memset(state, 0, sizeof(state));
  
  for (i=0, idx=0; i<1024; i++) {
    state[idx] ^= p[i];
    idx++;
    if (idx==64) {
      norx(state);
      idx = 0;
    }
  }
  bin2hex("state", state, 64);
	return 0;
}
