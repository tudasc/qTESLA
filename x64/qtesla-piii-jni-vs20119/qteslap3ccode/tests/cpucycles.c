/********************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: utility functions for testing and benchmarking
*********************************************************************************************/

#include "cpucycles.h"
#include <time.h>

#ifdef _WIN32
# include <intrin.h>
#endif

uint64_t cpucycles(void)
{
#ifdef _WIN32
	// _mm_lfence();  // optionally wait for earlier insns to retire before reading the clock
	uint64_t tsc = (uint64_t)__rdtsc();
	// _mm_lfence();  // optionally block later instructions until rdtsc retires
	return tsc;
#else
	// Access system counter for benchmarking
	unsigned int hi, lo;

	asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
	return (uint64_t)((int64_t)lo) | (((int64_t)hi) << 32);
#endif

}
