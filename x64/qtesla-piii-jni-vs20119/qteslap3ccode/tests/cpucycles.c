/********************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: utility functions for testing and benchmarking
*********************************************************************************************/

#define OS_LINUX    1
#define OS_TARGET OS_LINUX

#include "cpucycles.h"
#if (OS_TARGET == OS_WIN)
  #include <intrin.h>
#elif (OS_TARGET == OS_LINUX) && (TARGET == TARGET_ARM || TARGET == TARGET_ARM64)
  #include <time.h>
#endif


int64_t cpucycles(void)
{ // Access system counter for benchmarking
#if (OS_TARGET == OS_WIN) && (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
  return __rdtsc();
#elif (OS_TARGET == OS_WIN) && (TARGET == TARGET_ARM)
  return __rdpmccntr64();
#elif (OS_TARGET == OS_LINUX) && (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
  unsigned int hi, lo;

  asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
  return ((int64_t)lo) | (((int64_t)hi) << 32);
#elif (OS_TARGET == OS_LINUX) && (TARGET == TARGET_ARM || TARGET == TARGET_ARM64)
  struct timespec time;

  clock_gettime(CLOCK_REALTIME, &time);
  return (int64_t)(time.tv_sec*1e9 + time.tv_nsec);
#else
  return 0;            
#endif
}