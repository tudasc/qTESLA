#ifndef __RANDOM_H__
#define __RANDOM_H__

// Generate random bytes and output the result to random_array
#ifdef _WIN32
void randombytesarray(unsigned char* random_array, unsigned int nbytes);
void randombytes(unsigned char* random_array, unsigned int nbytes);
#else
void randombytes(unsigned char* random_array, unsigned int nbytes);
#endif

#endif
