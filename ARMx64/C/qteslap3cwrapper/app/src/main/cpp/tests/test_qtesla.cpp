/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: testing and benchmarking code
**************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <string>
#include <omp.h>
#include "../random/random.h"
#include "cpucycles.h"
#include "../api.h"
#include "../poly.h"
#include "../pack.h"
#include "../sample.h"
#include "../params.h"
#include "../sha3/fips202.h"
#include "test_qtesla.h"
#include "Logger.h"

// For RSA Test
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

using namespace std;
  
#if (OS_TARGET == OS_LINUX)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif

#define MLEN 200
//#define NRUNS 5000
#define NTESTS 100


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


//unsigned char mi[MLEN];
unsigned char mo[MLEN+CRYPTO_BYTES];
unsigned char sm[MLEN+CRYPTO_BYTES];
unsigned char pk[CRYPTO_PUBLICKEYBYTES];
unsigned char sk[CRYPTO_SECRETKEYBYTES];
unsigned long long smlen, mlen;

extern unsigned long long rejwctr;
extern unsigned long long rejyzctr;
extern unsigned long long ctr_keygen;
extern unsigned long long ctr_sign;


#ifdef DEBUG  

int print_accrates()
{
  int r;
  double rejw=.0, rejyz=.0, rejctr=.0, rejctrkg=.0;
  unsigned long long i, j;

  for (i=0; i<NTESTS; i++){
    crypto_sign_keypair(pk, sk);
    rejctrkg+=ctr_keygen;
  }

  // Print acceptance rate for keygen. The counter increased by PARAM_K for each try
  printf("Acceptance rate of Keygen : %.2f\n", (double)((PARAM_K+1)*NTESTS)/((double)rejctrkg)); fflush(stdout);
 
  for (i=0; i<NTESTS; i++)
  {
    randombytes(mi, MLEN);
    crypto_sign(sm, &smlen, mi, MLEN, sk);    
    rejctr+=ctr_sign;
    rejw+=rejwctr;
    rejyz+=rejyzctr;
  }
  
  printf("Acceptance rate of v\t  : %.2f\n",1/((rejw/NTESTS)+1));
  printf("Acceptance rate of z\t  : %.2f\n",1/((rejyz/(NTESTS+rejw))+1));
  printf("Acceptance rate of Signing: %.2f\n",(double)NTESTS/rejctr);
  printf("\n");
 
  return 0;
}

#endif


int mainTest(int numruns, int signsperrun, string& s, int bitflag, int rsabitlen)
{

  const int NRUNS =  numruns;
  unsigned int i, j;
  unsigned char r;
  int valid, response;
  int padding = RSA_PKCS1_PADDING;
    int bitlen = rsabitlen;//2048;//6144;//2048; //4096; //6144;


  unsigned char** mis; // Messages for the tests
    unsigned char encrypted[7144];
    unsigned char decrypted[7144];

    Logger::instance().clear();

    Logger::instance().pushMessage("===============\n");
  char buffer[300];
  sprintf(buffer, "Testing signature schemes qTESLA, system %s and RSA-%d, tests for %d iterations @ %d signings\n",
          CRYPTO_ALGNAME, bitlen, NRUNS, signsperrun);
  Logger::instance().pushMessage(buffer);
  sprintf(buffer, "===============\n");
  //sprintf(buffer, "Bitflag %i .\n", bitflag);
  Logger::instance().pushMessage(buffer);

  printf("\nCRYPTO_PUBLICKEY_BYTES: %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEY_BYTES: %d\n", (int)CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_SIGNATURE_BYTES: %d\n\n", CRYPTO_BYTES);

  // Create all messages required to have the same per encode/decode
  mis = (unsigned char **)malloc(NRUNS * sizeof(unsigned char* ));
  for(i=0; i < NRUNS; i++) {
      mis[i] = (unsigned char *) malloc(MLEN * sizeof(unsigned char));
      //randombytes(mis[i], MLEN);
      for (int kk = 0; kk < MLEN; kk++) {
          int val =  ((((kk+51)*19)%7) + ((i+41)*29) * ((kk%31 + i + 3) * 13));
          mis[i][j] = (char)val;
      }
      //mis[i][MLEN] = 0;
  }



  double signtime = 0;
  double verifytime = 0;
  double keygentime = 0;


// Run qtesla if requested
    if ((bitflag >> 0) & 1U)
    {
        for (i = 0; i < NRUNS; i++) {
            double keygenstart = omp_get_wtime();
            crypto_sign_keypair(pk, sk);
            keygentime += omp_get_wtime() - keygenstart;

            for (int sr = 0; sr < signsperrun; sr++) {

                double signstart = omp_get_wtime();
                crypto_sign(sm, &smlen, mis[i], MLEN, sk);
                signtime += (omp_get_wtime() - signstart);

                double verifystart = omp_get_wtime();
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
                        printf("crypto_sign_open returned BAD message value. \n");
                        return -1;
                    }
                }
                verifytime += omp_get_wtime() - verifystart;
            }
        }

        sprintf(buffer, "[qtesla] Keygentime : %.2f s  (%.1f ops/s).\n",
                keygentime, 1.0 / (keygentime/(NRUNS)));
        Logger::instance().pushMessage(buffer);
        sprintf(buffer, "[qtesla] Signtime: %.2f s (%.1f ops/s).\n",
                signtime, 1.0 / (signtime/(signsperrun*NRUNS)));
        Logger::instance().pushMessage(buffer);
        sprintf(buffer, "[qtesla] Verifytime : %.2f s (%.1f ops/s).\n",
                verifytime, 1.0 / (verifytime/(signsperrun*NRUNS)));
        Logger::instance().pushMessage(buffer);
    }


  // Second round with RSA if requested
  keygentime = 0;
  signtime = 0;
  verifytime = 0;

    //unsigned char* tencrypted = (unsigned char* )malloc(sizeof(unsigned char) * 7144);
   // unsigned char* tdecrypted = (unsigned char* )malloc(sizeof(unsigned char) * 7144);

    if ((bitflag >> 1) & 1U)
    {
        for (i = 0; i < NRUNS; i++) {
            RSA *rsa = NULL;
            unsigned long	e = RSA_F4;
            BIGNUM			*bne = NULL;
            int				ret = 0;

            // Generate RSA-key
            double keygenstart = omp_get_wtime();
            bne = BN_new();
            ret = BN_set_word(bne,e);
            if(ret != 1) {
                sprintf(buffer, "BN_set_word error.\n");
                printf("BN_set_word error.\n");
                return 201;
            }

            rsa = RSA_new();
            ret = RSA_generate_key_ex(rsa, bitlen, bne, NULL);
            if(ret != 1){
                sprintf(buffer, "RSA_generate_key_ex failed.\n");
                Logger::instance().pushMessage(buffer);
                printf("RSA_generate_key_ex failed.\n");
                return 202;
            }
            keygentime += omp_get_wtime() - keygenstart;

            for (int sr = 0; sr < signsperrun; sr++) {
                double singstart = omp_get_wtime();
                int encrypted_length = RSA_private_encrypt(100, mis[i], encrypted, rsa, padding);
                signtime += (omp_get_wtime() - singstart);

                int verifystart = omp_get_wtime();
                if(encrypted_length == -1)
                {
                    sprintf(buffer, "Private Encrypt failed.\n");
                    Logger::instance().pushMessage(buffer);
                    printf("Private Encrypt failed");
                    return 203;
                }

                int  decrypted_length = RSA_public_decrypt(encrypted_length, encrypted, decrypted, rsa, padding);
                if(decrypted_length == -1)
                {
                    sprintf(buffer, "Public Decrypt failed.\n");
                    Logger::instance().pushMessage(buffer);
                    printf("Public Decrypt failed");
                    return 204;
                }

                verifytime += omp_get_wtime() - verifystart;
            }
            RSA_free(rsa);
        }

        sprintf(buffer, "[RSA-%d] Keygentime : %.2f s  (%.1f ops/s).\n",
                bitlen, keygentime, 1.0 / (keygentime/(NRUNS)));
        Logger::instance().pushMessage(buffer);
        sprintf(buffer, "[RSA-%d] Signtime: %.2f s (%.1f ops/s).\n",
                bitlen, signtime, 1.0 / (signtime/(signsperrun*NRUNS)));
        Logger::instance().pushMessage(buffer);
        sprintf(buffer, "[RSA-%d] Verifytime : %.2f s (%.1f ops/s).\n",
                bitlen, verifytime, 1.0 / (verifytime/(signsperrun*NRUNS)));
        Logger::instance().pushMessage(buffer);
    }


    // Third run with ECDSA if requested
    keygentime = 0;
    signtime = 0;
    verifytime = 0;

    if ((bitflag >> 3) & 1U) {
        for (int i = 0; i < NRUNS; i++) {
            double keygenstart = omp_get_wtime();
            // Create the keypair and check
            // Public and private key are encoded in ec_key
            EC_KEY *ec_key = EC_KEY_new_by_curve_name(
                    NID_secp384r1); ///NID_brainpoolP384r1 //NID_secp384r1 // NID_secp384r1 // NID_X9_62_prime256v1
            assert(1 == EC_KEY_generate_key(ec_key));
            assert(1 == EC_KEY_check_key(ec_key));
            keygentime += omp_get_wtime() - keygenstart;

            for (int ii = 0; ii < signsperrun; ii++) {
                unsigned int sig_len = ECDSA_size(ec_key);
                unsigned int buff_len = strlen((const char *) mis[i]);
                unsigned char *sig;

                sig = (unsigned char *) OPENSSL_malloc(sig_len);
                double singstart = omp_get_wtime();
                if (ECDSA_sign(0, mis[i], buff_len, sig, &sig_len, ec_key) == 0) {
                    cout << "ECDSA Signing failed" << endl;
                }
                signtime += (omp_get_wtime() - singstart);


                double verifystart = omp_get_wtime();
                if (ECDSA_verify(0, mis[i], buff_len, sig, sig_len, ec_key) != 1) {
                    sprintf(buffer, "[ECDSA] Verify failed!");
                    Logger::instance().pushMessage(buffer);
                    return 304;
                }
                verifytime += omp_get_wtime() - verifystart;

            }
            EC_KEY_free(ec_key);
        }

        sprintf(buffer, "[ECDSA] Keygentime : %.2f s  (%.1f ops/s).\n",
                keygentime, 1.0 / (keygentime / (NRUNS)));
        Logger::instance().pushMessage(buffer);
        sprintf(buffer, "[ECDSA] Signtime: %.2f s (%.1f ops/s).\n",
                signtime, 1.0 / (signtime / (signsperrun * NRUNS)));
        Logger::instance().pushMessage(buffer);
        sprintf(buffer, "[ECDSA] Verifytime : %.2f s (%.1f ops/s).\n",
                verifytime, 1.0 / (verifytime / (signsperrun * NRUNS)));
        Logger::instance().pushMessage(buffer);
    }
  return 0;
}
