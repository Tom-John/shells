


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <mpir.h>

int main(int argc, char *argv[])
{
  mpz_t b, e, m, r;
  
  if (argc != 4) {
    printf("usage: mz <base> <exponent> <modulus>\n");
    return 0;
  }
  
  mpz_inits(b, e, m);  
  mpz_set_str(b, argv[1], 10); 
  mpz_set_str(e, argv[2], 10); 
  mpz_set_str(m, argv[3], 10); 
  mpz_powm(r, b, e, m);
  
  mpz_out_str(stdout, 10, r);
  
  mpz_clears(b, e, m, r);
  return 0;
}


