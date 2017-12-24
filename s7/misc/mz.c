


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <gmp.h>

int main(int argc, char *argv[])
{
	  mpz_t b, e, m, r;
	  
	  if (argc != 4) {
		printf("usage: mz <base> <exponent> <modulus>\n");
		return 0;
	  }
	  
	  mpz_init(b); mpz_init(e); mpz_init(m); mpz_init(r);  
	  
	  mpz_set_str(b, argv[1], 10); 
	  mpz_set_str(e, argv[2], 10); 
	  mpz_set_str(m, argv[3], 10); 
	  
	  mpz_out_str(stdout, 10, b);
	  putchar('\n');
	  
	  mpz_out_str(stdout, 10, e);
	  putchar('\n');
	  	  
	  mpz_out_str(stdout, 10, m);
	  putchar('\n');
	  	  
	  mpz_powm(r, b, e, m);
	  
	  mpz_out_str(stdout, 10, r);
	  putchar('\n');
	  
	  mpz_clear(b); mpz_clear(e); mpz_clear(m); mpz_clear(r);
	  return 0;
}


