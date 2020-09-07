/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: testing and benchmarking code
**************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <omp.h>
#include <string.h>
#include <openssl/engine.h>
#include <assert.h>

#include "../random/random.h"
#include "cpucycles.h"
#include "../api.h"
#include "../poly.h"
#include "../pack.h"
#include "../sample.h"
#include "../params.h"
#include "../sha3/fips202.h"
#include "../qTeslaTestJNI.h"

#ifdef __linux__
#if (OS_TARGET == OS_LINUX)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif
#endif

#ifdef _WIN32
#include <stdio.h> 
#include <stdlib.h> 
#include <time.h>
#endif

#define MLEN 280
//#define NRUNS 5000
#define NTESTS 1


#define CHECK_BIT(var,pos) (bool)((var) & (1<<(pos)))


static int cmp_llu(const void *a, const void*b)
{
  if (*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if (*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}


static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if (llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}


static unsigned long long average(unsigned long long *t, size_t tlen)
{
  unsigned long long acc=0;
  size_t i;
  for (i=0; i<tlen; i++)
    acc += t[i];
  return acc/(tlen);
}


static void print_results(const char *s, unsigned long long *t, size_t tlen)
{
  printf("%s", s);
  printf("\n");
  printf("median:  %llu ", median(t, tlen));  print_unit; printf("\n");
  printf("average: %llu ", average(t, tlen-1));  print_unit; printf("\n");
  printf("\n");
}


unsigned char mo[MLEN+CRYPTO_BYTES];
unsigned char sm[MLEN+CRYPTO_BYTES];
unsigned char pk[CRYPTO_PUBLICKEYBYTES];
unsigned char sk[CRYPTO_SECRETKEYBYTES];
unsigned long long smlen, mlen;

extern unsigned long long rejwctr;
extern unsigned long long rejyzctr;
extern unsigned long long ctr_keygen;
extern unsigned long long ctr_sign;


#ifdef __STATS__   

int print_accrates()
{
	double rejw = .0, rejyz = .0, rejctr = .0, rejctrkg = .0;
	unsigned long long i;

	for (i = 0; i<NTESTS; i++) {
		crypto_sign_keypair(pk, sk);
		rejctrkg += ctr_keygen;
	}

	// Print acceptance rate for keygen. The counter increased by PARAM_K for each try
	printf("Acceptance rate of Keygen : %.2f\n", (double)((PARAM_K + 1)*NTESTS) / ((double)rejctrkg)); fflush(stdout);

	for (i = 0; i<NTESTS; i++)
	{
		randombytesarray(mi, MLEN);
		crypto_sign(sm, &smlen, mi, MLEN, sk);
		rejctr += ctr_sign;
		rejw += rejwctr;
		rejyz += rejyzctr;
	}



	printf("Acceptance rate of v\t  : %.2f\n", 1 / ((rejw / NTESTS) + 1));
	printf("Acceptance rate of z\t  : %.2f\n", 1 / ((rejyz / (NTESTS + rejw)) + 1));
	printf("Acceptance rate of Signing: %.2f\n", (double)NTESTS / rejctr);
	printf("\n");

	return 0;
}

void test_functions()
{
	unsigned int i;
	unsigned long long cycles0[NTESTS];
	int nonce;
	poly t, a, s, e, y, y_ntt, v, z;
	unsigned char randomness[CRYPTO_RANDOMBYTES];
	unsigned char c[CRYPTO_C_BYTES], seed[2 * CRYPTO_SEEDBYTES], randomness_extended[4 * CRYPTO_SEEDBYTES];
	unsigned char hm[HM_BYTES], ss[PARAM_N];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	uint32_t pos_list[PARAM_H];
	int16_t sign_list[PARAM_H], ee[PARAM_N];
	int32_t pk_t[PARAM_N];

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		randombytes(randomness, CRYPTO_RANDOMBYTES);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("randombytes: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		SHAKE(randomness_extended, 4 * CRYPTO_SEEDBYTES, randomness, CRYPTO_RANDOMBYTES);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("SHAKE: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		SHAKE(randomness_extended, HM_BYTES, mi, MLEN);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("SHAKE: ", cycles0, NTESTS);

	nonce = 0;

	/*for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		poly_uniform(a, randomness);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("GenA: ", cycles0, NTESTS);*/

	nonce = 0;
	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		sample_y(y, randomness, nonce++);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("ySampler: ", cycles0, NTESTS);

	/*for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		hash_H(c, v, hm);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("H: ", cycles0, NTESTS);*/

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		encode_c(pos_list, sign_list, c);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Enc: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		sparse_mul8(t, ss, pos_list, sign_list);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Sparse mul8: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		sparse_mul32(t, pk_t, pos_list, sign_list);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Sparse mul32: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		poly_ntt(y_ntt, y);
		poly_mul(t, a, y_ntt);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Poly mul: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		poly_add(t, a, t);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Poly add: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		poly_add_correct(t, a, t);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Poly add with correction: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		poly_sub(t, a, t);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Poly sub: ", cycles0, NTESTS);

	/*for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		encode_pk(pk, t, seed);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Encode pk: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		decode_pk(pk_t, seed, pk);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Decode pk: ", cycles0, NTESTS);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		encode_sig(sm, c, z);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Encode sig: ", cycles0, NTESTS);*/

	randombytes(mi, MLEN);
	crypto_sign_keypair(pk, sk);
	crypto_sign(sm, &smlen, mi, MLEN, sk);

	for (i = 0; i < NTESTS; i++) {
		cycles0[i] = cpucycles();
		decode_sig(c, z, sm);
		cycles0[i] = cpucycles() - cycles0[i];
	}
	print_results("Decode sig: ", cycles0, NTESTS);

	printf("\n");
}

#endif


int main(int argc, char *argv[])
{
	bool check_qtesla;
	bool check_ecdsa=false;
	bool check_rsa=false;


#ifdef _WIN32
	time_t t;
	srand((unsigned)time(&t));
#endif

  unsigned int i, j, ii;
  unsigned int signsperrun, NRUNS;
  unsigned char r;
  
  int valid, response;
  
  		if(argc < 3) {
			printf("Not enough arguments. Running with default values.\n");
			NRUNS = 15;
			signsperrun = 1;
		}
		
		else if (argc == 3)
		{
			NRUNS = atoi(argv[1]);
			signsperrun = atoi(argv[2]);		
		}

		else if (argc == 4)
		{
			NRUNS = atoi(argv[1]);
			signsperrun = atoi(argv[2]);

			int test = atoi(argv[3]);
			check_qtesla = CHECK_BIT(test, 0);
			check_ecdsa = CHECK_BIT(test, 1);
			check_rsa = CHECK_BIT(test, 2);

		}

		else if (argc == 5)
		{
			NRUNS = atoi(argv[1]);
			signsperrun = atoi(argv[2]);

			int test = atoi(argv[3]);
			check_qtesla = CHECK_BIT(test, 0);
			check_ecdsa = CHECK_BIT(test, 1);
			check_rsa = CHECK_BIT(test, 2);

			int num = atoi(argv[4]);
			printf("%d threads\n", num);
			omp_set_num_threads(num);
		}
    
  printf("\n");
  printf("===========================================================================================\n");
  printf("Testing signature scheme qTESLA, system %s, tests for %d iterations @ %d signings.\n", CRYPTO_ALGNAME, NRUNS, signsperrun);
  printf("===========================================================================================\n");

  printf("\nCRYPTO_PUBLICKEY_BYTES: %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEY_BYTES: %d\n", (int)CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_SIGNATURE_BYTES: %d\n\n", CRYPTO_BYTES);

#ifdef __STATS__  
  print_accrates();
  test_functions();
#endif

	double tstart = omp_get_wtime();;
	double signtime = 0.0;

	double start_gen;
	double end_gen;

	double start_sign;
	double end_sign;

	double start_verify;
	double end_verify;

	double gen_h_time = 0.0;
	double sign_h_time = 0.0;
	double verify_h_time = 0.0;

	clock_t cbegin, cend=0;
	double tt;

	  // Create all messages required to have the same per encode/decode
	unsigned char ** mis = (unsigned char **)malloc(NRUNS * sizeof(unsigned char* ));
	  // seed for random generator
	  srand(time(0));
	  for(i=0; i < NRUNS; i++) {
		  mis[i] = (unsigned char *)malloc(MLEN * sizeof(unsigned char));
		  //randombytes(mis[i], MLEN);

		  for(int j=0; j<MLEN; j++) {
			  int val =  ((((j+51)*19)%7) + ((i+41)*29) * ((j%31 + i + 3) * 13));
			  mis[i][j] = (char)val;
		  }
	  }


	  char* smes = "data";

	if (check_qtesla)
	{
	  for (i = 0; i < NRUNS; i++) {


		start_gen = omp_get_wtime();
		crypto_sign_keypair(pk, sk);
		//crypto_sign_keypair_pthread_wrapper(pk, sk, 4);
		end_gen = omp_get_wtime();
		gen_h_time += end_gen - start_gen;

		cbegin = clock();
		for(ii = 0; ii < signsperrun; ii++)	{
			start_sign = omp_get_wtime();
			//crypto_sign(sm, &smlen, smes, 4, sk);
			crypto_sign(sm, &smlen, mis[i], MLEN, sk);
			sign_h_time += (omp_get_wtime() - start_sign);

			start_verify = omp_get_wtime();
			valid = crypto_sign_open(mo, &mlen, sm, smlen, pk);

			if (valid != 0) {
			  printf("Signature verification FAILED. \n");
			  return -1;
			} else if (mlen != MLEN) {
			  printf("crypto_sign_open returned BAD message length. \n");
			  return -1;
			}

			for (j = 0; j < mlen; j++) {
			  if (mis[i][j] != mo[j]) {
				printf ("crypto_sign_open returned BAD message value. \n");
				return -1;
			  }
			}

			// Change something in the signature somewhere
/*	#ifdef _WIN32
			randombytesarray(&r, 1);
	#else
			randombytes(&r, 1);
	#endif

			sm[r % (MLEN+CRYPTO_BYTES)] ^= 1;
			response = crypto_sign_open(mo, &mlen, sm, smlen, pk);
			if (response == 0) {
			  printf("Corrupted signature VERIFIED. \n");
			  return -1;
			}*/
			verify_h_time += omp_get_wtime() - start_verify;
		  }
		cend += clock() - cbegin;
	  }

	  printf("[QTESLA-P3] Keygen: %f sec and %f ops/s.\n", gen_h_time, 1.0 / ( gen_h_time / NRUNS ));
	  printf("[QTESLA-P3] Sign: %f sec and %f ops/s.\n", sign_h_time, 1.0 / ( sign_h_time / (NRUNS * signsperrun ) ));
	  printf("[QTESLA-P3] Verify: %f sec and %f ops/s.\n", verify_h_time, 1.0 / ( verify_h_time / (NRUNS * signsperrun) ));
	  tt = (double)(cend) / (double)CLOCKS_PER_SEC;
	  printf("[QTESLA-P3] Keygen: %f sec\n", tt);
	}

	  // Second round with ECDSA
	if(check_ecdsa)
	{
	  gen_h_time = 0.0;
	  verify_h_time = 0.0;
	  sign_h_time = 0.0;

	  for (i = 0; i < NRUNS; i++) {
		// Create the keypair and check
		// Public and private key are encoded in ec_key
		  double startkeygen = omp_get_wtime();
		EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp384r1); //NID_secp384r1//NID_secp384r1//NID_brainpoolP384r1
		assert(1==EC_KEY_generate_key(ec_key));
		assert(1==EC_KEY_check_key(ec_key));
		gen_h_time += omp_get_wtime() - startkeygen;

		  for(ii = 0; ii < signsperrun; ii++)	{
			  unsigned int sig_len = ECDSA_size(ec_key);
			  unsigned int buff_len = strlen((const char*)mis[i]);
			  unsigned char* sig;

			  sig  = (unsigned char*)OPENSSL_malloc(sig_len);
			  double singstart = omp_get_wtime();
			    if (ECDSA_sign(0, mis[i], buff_len, sig, &sig_len, ec_key) == 0) {
			    	printf("ECDSA Signing failed.\n");
			    }
			    sign_h_time += (omp_get_wtime() - singstart);

			    double verifystart = omp_get_wtime();
			   if (ECDSA_verify(0, mis[i], buff_len, sig, sig_len, ec_key) != 1) {
				   printf("Error in Verify.\n");
			   }
			   verify_h_time +=  omp_get_wtime() - verifystart;

		  }
		  EC_KEY_free(ec_key);
	  }

	  printf("[ECDSA] Keygen: %f sec and %f ops/s.\n", gen_h_time, 1.0 / ( gen_h_time / NRUNS ));
	  printf("[ECDSA] Sign: %f sec and %f ops/s.\n", sign_h_time, 1.0 / ( sign_h_time / (NRUNS * signsperrun ) ));
	  printf("[ECDSA] Verify: %f sec and %f ops/s.\n", verify_h_time, 1.0 / ( verify_h_time / (NRUNS * signsperrun) ));

	}

	 // Third run with RSA
	if(check_rsa)
	{
		 unsigned char encrypted[7144];
		 unsigned char decrypted[7144];
		 int padding = RSA_PKCS1_PADDING;

	  gen_h_time = 0.0;
	  verify_h_time = 0.0;
	  sign_h_time = 0.0;

	  tstart = omp_get_wtime();;
	  signtime = 0.0;
	  int bitlen = 6144; //4096; //6144;

	  for (i = 0; i < NRUNS; i++) {
			 int keylen;
			 RSA *rsa = NULL;
			 unsigned long	e = RSA_F4;
			 BIGNUM			*bne = NULL;
			 int				ret = 0;

			 // Generate RSA-key
			 double startkeygen = omp_get_wtime();
			 bne = BN_new();
			 ret = BN_set_word(bne,e);
			 if(ret != 1) {
				 printf("BN_set_word error.\n");
			 }

			 rsa = RSA_new();
			 ret = RSA_generate_key_ex(rsa, bitlen, bne, NULL);
			if(ret != 1){
				printf("RSA_generate_key_ex failed.\n");
			}
			gen_h_time += omp_get_wtime() - startkeygen;


		  for(ii = 0; ii < signsperrun; ii++)	{
			  double singstart = omp_get_wtime();
			  int encrypted_length = RSA_private_encrypt(MLEN, mis[i], encrypted, rsa, padding);
			  sign_h_time += (omp_get_wtime() - singstart);

			  //printf("Uncrypt len: %d, Crypted len: %d \n", MLEN, encrypted_length);

			  double verifystart = omp_get_wtime();
			  if(encrypted_length == -1)
			  {
				  printf("Private Encrypt failed");
				  exit(0);
			  }

			  int  decrypted_length = RSA_public_decrypt(encrypted_length, encrypted, decrypted, rsa, padding);
			  if(decrypted_length == -1)
			  {
				  printf("Public Decrypt failed");
				  exit(0);
			  }
			  verify_h_time +=  omp_get_wtime() - verifystart;
		  }
		  RSA_free(rsa);
	  }
	  printf("[RSA-6144] Keygen: %f sec and %f ops/s.\n", gen_h_time, 1.0 / ( gen_h_time / NRUNS ));
	  printf("[RSA-6144] Sign: %f sec and %f ops/s.\n", sign_h_time, 1.0 / ( sign_h_time / (NRUNS * signsperrun ) ));
	  printf("[RSA-6144] Verify: %f sec and %f ops/s.\n", verify_h_time, 1.0 / ( verify_h_time / (NRUNS * signsperrun) ));
	}

	double ttime = omp_get_wtime() - tstart;
	printf("Finishing all test after %f sec.\n", ttime);

	//scanf("%d", ttime);
	return 0;
}
