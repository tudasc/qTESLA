/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: testing and benchmarking code
**************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <omp.h>
#include <string.h>
#include <omp.h>
#include "jni.h"
#include "sctudarmstadt_qtesla_cwrapper_qTeslaTestJNI.h"

#include "random/random.h"
#include "tests/cpucycles.h"
#include "api.h"
#include "poly.h"
#include "pack.h"
#include "sample.h"
#include "params.h"
#include "sha3/fips202.h"

// Pythread

//#include <mutex>
//#include <condition_variable>
  
#ifdef __linux__
#include <pthread.h>
#if (OS_TARGET == OS_LINUX)
  #include <sys/types.h>

  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif
#endif



#ifdef __linux__
pthread_mutex_t mymutex;
pthread_cond_t mycondition;

pthread_mutex_t mymutex2;
pthread_cond_t mycondition2;
#endif

bool can_run;
int paronce;
int gnt;

typedef struct {
	unsigned char* pk;
	unsigned char* sk;
	unsigned char* flag;
} keygenparams;

unsigned char endflag[1];

#ifdef __linux__
void* crypto_sign_keypair_pthread_perthread(void* params) {
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	// WIthout malloc since threads will be cancelled
	unsigned char my_pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char my_sk[CRYPTO_SECRETKEYBYTES];

	// Derefer input
	keygenparams *d_params = (keygenparams*)params;

	// Call the key_gen
	paronce++;
	int ret = crypto_sign_keypair_par( my_pk, my_sk, paronce, gnt   );

	// notify
	pthread_mutex_lock(&mymutex);
	if(d_params->flag[0] == 0) {

		// Active Waiting
		long long is=0;
		while(!can_run) {
			 is++;
		}

		pthread_cond_signal(&mycondition); //wake up thread 1
		d_params->flag[0] = 1;//(char)is + 1;

		// The first uses its result
		for(int i=0; i < CRYPTO_PUBLICKEYBYTES; i++) {
			d_params->pk[i] = my_pk[i];
		}

		for(int i=0; i < CRYPTO_SECRETKEYBYTES; i++) {
			d_params->sk[i] = my_sk[i];
		}
	}
	pthread_mutex_unlock(&mymutex);
}

int crypto_sign_keypair_pthread_wrapper(unsigned char *pk, unsigned char *sk, int _nt) {
	paronce = -1;
	gnt = _nt;

	// Pack input
	endflag[0] = 0;

	keygenparams inparams;
	inparams.pk = pk;
	inparams.sk = sk;
	inparams.flag = endflag;

	// Instantiate pThreads and let them search for a result
	pthread_t* threadis = (pthread_t*)malloc (gnt * sizeof(pthread_t));

	for(int i=0; i<gnt; i++) {
		if(pthread_create(   &threadis[i], NULL, &crypto_sign_keypair_pthread_perthread, &inparams)) {
			fprintf(stderr, "Error creating thread\n");
		}
	}
	// Allow threads towirte the result
	can_run = true;

	// Wait for the result
	pthread_mutex_lock(&mymutex);
	pthread_cond_wait(&mycondition, &mymutex); //wait for the condition
	pthread_mutex_unlock(&mymutex);

	// Cancelling ending
	for(int i=0; i<gnt; i++) {
		pthread_cancel(threadis[i]);
	}
	free(threadis);
	return 0;

}
#endif
int checkQTesla (int runs, int signs, const char* c_message)
{	
	const size_t MLEN = strlen(c_message);

	/*unsigned char mi[MLEN];
	unsigned char mo[MLEN+CRYPTO_BYTES];
	unsigned char sm[MLEN+CRYPTO_BYTES];*/

	unsigned char* mi = (unsigned char*)malloc( MLEN * sizeof(unsigned char) );
	unsigned char* mo =  (unsigned char*)malloc( (MLEN+CRYPTO_BYTES) * sizeof(unsigned char) );
	unsigned char* sm =  (unsigned char*)malloc( (MLEN+CRYPTO_BYTES) * sizeof(unsigned char) );

	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned long long smlen, mlen;	

  unsigned int i, j, ii;
  unsigned int signsperrun, NRUNS;
  unsigned char r;
  
  int valid, response;  
  
  NRUNS = runs;
  signsperrun = signs;		
    
  printf("\n");
  printf("===========================================================================================\n");
  printf("Testing signature scheme qTESLA, system %s, tests for %d different keypairs @ %d signings / verifies each.\n", CRYPTO_ALGNAME, NRUNS, signsperrun);
  printf("===========================================================================================\n");

  printf("\nCRYPTO_PUBLICKEY_BYTES: %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEY_BYTES: %d\n", (int)CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_SIGNATURE_BYTES: %d\n\n", CRYPTO_BYTES);


printf("\nLength of message to sing \" %s \" passed is: %zd\n", c_message, MLEN);

	int linecnt=0;
	double tstart = omp_get_wtime();
//	printf("LINE: %d\n", ++linecnt);
	double signtime = 0.0;
  for (i = 0; i < NRUNS; i++) {
    //randombytes(mi, MLEN);	
		crypto_sign_keypair(pk, sk);

	for(ii = 0; ii < signsperrun; ii++)	{	
		double singstart = omp_get_wtime();
		crypto_sign(sm, &smlen, mi, MLEN, sk);
		signtime += (omp_get_wtime() - singstart);
		valid = crypto_sign_open(mo, &mlen, sm, smlen, pk);
		if (valid != 0) {
		  printf("Signature verification FAILED. \n");
		  return -1;
		} else if (mlen != MLEN) {
		  printf("crypto_sign_open returned BAD message length. \n");
		  return -1;
		}

		for (j = 0; j < mlen; j++) {
		  if (mi[j] != mo[j]) {
			printf ("crypto_sign_open returned BAD message value. \n");
			return -1;
		  }
		}

		// Change something in the signature somewhere    
#ifdef _WIN32
		randombytesarray(&r, 1);
#else
		randombytes(&r, 1);
#endif
		sm[r % (MLEN+CRYPTO_BYTES)] ^= 1;
		response = crypto_sign_open(mo, &mlen, sm, smlen, pk);
		if (response == 0) {
		  printf("Corrupted signature VERIFIED. \n");
		  return -1;
		}
	  }
  }
  
  double ttime = omp_get_wtime() - tstart;
  printf("Finishing after %f sec with signing: %f sec.\n", ttime, signtime);
	free(mi);
	free(mo);
	free(sm);
  return 0;
}

JNIEXPORT jint JNICALL Java_sctudarmstadt_qtesla_cwrapper_qTeslaTestJNI_checkQTesla
  (JNIEnv * jnienv, jobject thisobj, jint runs, jint signs, jstring in_message) {

	const char *c_message = (*jnienv)->GetStringUTFChars(jnienv, in_message, 0);
	checkQTesla (runs, signs, c_message);
	return 0;	
}


JNIEXPORT jint JNICALL Java_sctudarmstadt_qtesla_cwrapper_qTeslaTestJNI_cryptoSignKeyPair
  (JNIEnv * jnienv, jobject thisobj, jbyteArray pk, jbyteArray sk, jint nt)
{
	unsigned char*  cPK = (unsigned char*)(*jnienv)->GetByteArrayElements(jnienv, pk, 0);
	jsize cPKsize = (*jnienv)->GetArrayLength(jnienv, pk);

	unsigned char*  cSK = (unsigned char*)(*jnienv)->GetByteArrayElements(jnienv, sk, 0);
	jsize cSKsize = (*jnienv)->GetArrayLength(jnienv, sk);

	omp_set_num_threads(nt);

	//int ret = crypto_sign_keypair_pthread_wrapper(cPK, cSK, nt);
	int ret = crypto_sign_keypair( cPK, cSK   );

	(*jnienv)->ReleaseByteArrayElements(jnienv, pk, cPK, 0);
	(*jnienv)->ReleaseByteArrayElements(jnienv, sk, cSK, 0);

	return ret;
}

JNIEXPORT jint JNICALL Java_sctudarmstadt_qtesla_cwrapper_qTeslaTestJNI_cryptoSign
  (JNIEnv * jnienv, jobject thisobj, jbyteArray sm, jlong insmsize, jbyteArray m, jlong inmsize, jbyteArray sk, jint nt)
{
	// Get the secret key
	unsigned char*  cSK = (unsigned char*)(*jnienv)->GetByteArrayElements(jnienv, sk, 0);
	jsize cSKsize = (*jnienv)->GetArrayLength(jnienv, sk);

	// Get the not-initialized signature
	unsigned char*  cSig = (unsigned char*)(*jnienv)->GetByteArrayElements(jnienv, sm, 0);
	jsize cSigsize = (*jnienv)->GetArrayLength(jnienv, sm);
	long long smlen = (long long)insmsize;

	// Get the message
	unsigned char*  cMes = (unsigned char*)(*jnienv)->GetByteArrayElements(jnienv, m, 0);
	jsize cMessize = (*jnienv)->GetArrayLength(jnienv, m);
	long long mlen = (long long)inmsize;

	omp_set_num_threads(nt);

	// Do stuff
	int ret = crypto_sign(
		cSig, &smlen,
		cMes, mlen,
		cSK
	);

	// Write new signature back
	(*jnienv)->ReleaseByteArrayElements(jnienv, sm, cSig, 0);
	// Release message and private key
	(*jnienv)->ReleaseByteArrayElements(jnienv, m, cMes, JNI_ABORT);
	(*jnienv)->ReleaseByteArrayElements(jnienv, sk, cSK, JNI_ABORT);
	return ret;
}

JNIEXPORT jint JNICALL Java_sctudarmstadt_qtesla_cwrapper_qTeslaTestJNI_cryptoVerify
  (JNIEnv * jnienv, jobject thisobj, jbyteArray m, jlong inmsize, jbyteArray sm, jlong insmsize, jbyteArray pk)
{
	// Get the secret key
	unsigned char*  cPK = (unsigned char*)(*jnienv)->GetByteArrayElements(jnienv, pk, 0);
	jsize cPKsize = (*jnienv)->GetArrayLength(jnienv, pk);

	// Get the signature
	unsigned char*  cSig = (unsigned char*)(*jnienv)->GetByteArrayElements(jnienv, sm, 0);
	jsize cSigsize = (*jnienv)->GetArrayLength(jnienv, sm);
	long long smlen = (long long)insmsize;

	// Get the empty message array
	unsigned char*  cMes = (unsigned char*)(*jnienv)->GetByteArrayElements(jnienv, m, 0);
	jsize cMessize = (*jnienv)->GetArrayLength(jnienv, m);
	long long mlen = (long long)inmsize;


	// Do stuff
	int ret = crypto_sign_open(
		cMes, &mlen,
		cSig, smlen,
		cPK
	    );

	// Write new message back
	(*jnienv)->ReleaseByteArrayElements(jnienv, m, cMes, 0);
	// Release message and private key
	(*jnienv)->ReleaseByteArrayElements(jnienv, sm, cSig, JNI_ABORT);
	(*jnienv)->ReleaseByteArrayElements(jnienv, pk, cPK, JNI_ABORT);

	return ret;
}

/*
 * Class:     qTeslaTestJNI
 * Method:    getPrivateKeySize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_sctudarmstadt_qtesla_cwrapper_qTeslaTestJNI_getPrivateKeySize
  (JNIEnv * env, jobject jobj) {
	return CRYPTO_SECRETKEYBYTES;
}

/*
 * Class:     qTeslaTestJNI
 * Method:    getPublicKeySize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_sctudarmstadt_qtesla_cwrapper_qTeslaTestJNI_getPublicKeySize
  (JNIEnv * env, jobject jobj) {
	return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Class:     qTeslaTestJNI
 * Method:    getSigatureSize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_sctudarmstadt_qtesla_cwrapper_qTeslaTestJNI_getSignatureSize
  (JNIEnv * env, jobject jobj) {
	return CRYPTO_BYTES;
}

