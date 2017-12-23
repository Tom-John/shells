
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <gmp.h>
#include "spp.h"
   
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
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
    
char *mpz_hex(mpz_t x)
{
    static char r[1024];
    
    mpz_get_str(r, 16, x);
    return r;
}

void key_xchg (spp_ctx *c)
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

    mpz_set_str (p, OAKLEY_PRIME_MODP2048, 16);
    mpz_set_str (g, "2", 16);
    
    // generate random 512-bit integer
    mpz_urandomb(y, state, 64);  
    
    // Bob obtains B = g ^ y mod p
    mpz_powm (B, g, y, p);

    // now wait for Alice to connect
    
    // send B to Alice
    
    // Bob computes session key
    mpz_powm (s2, A, y, p);  
    
    mpz_export(px, NULL, -1, 1, 0, 0, p);
    mpz_export(gx, NULL, -1, 1, 0, 0, g);
    mpz_export(xx, NULL, -1, 1, 0, 0, x);
    mpz_export(yx, NULL, -1, 1, 0, 0, y);  

    mpz_clear (s2);
    mpz_clear (s1);
    mpz_clear (p);
    mpz_clear (g);
    mpz_clear (y);
    mpz_clear (x);
    mpz_clear (B);
    mpz_clear (A);
}
