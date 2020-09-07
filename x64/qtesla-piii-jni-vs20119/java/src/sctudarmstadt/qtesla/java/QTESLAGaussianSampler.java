/******************************************************************************
* qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
*
* Portable and Constant-Time Gaussian Sampler
* 
* @author Yinhua Xu
*******************************************************************************/

package sctudarmstadt.qtesla.java;

public class QTESLAGaussianSampler {
	
	/**
	 * Chunk Size for Sampling
	 */
	public static final int CHUNK = 512;
	
	/** 
	 * Dimension, (Dimension - 1) is the Polynomial Degree
	 */
	private static int n;
	
	/**
	 * Row Size of the Cumulative Distributed Table
	 */
	private static int row;
	
	/**
	 * Column Size of the Cumulative Distributed Table
	 */
	private static int column;
	
	/**
	 * Cumulative Distributed Table
	 */
	private static long[] cumulativeDistributedTable;	
	private static int[] cumulativeDistributedTable_MB;
	
	public int getN () {
		
		return n;
		
	}
	
	/*****************************************************************************************************
	 * Gaussian Sampler Constructor
	 * 
	 * @param parameterSet		qTESLA Parameter Set
	 *****************************************************************************************************/
	public QTESLAGaussianSampler (String parameterSet) {
		cumulativeDistributedTable_MB = CumulativeDistributedTable.CUMULATIVE_DISTRIBUTED_TABLE_P_III_MB;
		if (parameterSet == "qTESLA-I") {
			
			n = 512;
			row = 209;
			column = 1;
			cumulativeDistributedTable = CumulativeDistributedTable.CUMULATIVE_DISTRIBUTED_TABLE_I;
			
		} else if (parameterSet == "qTESLA-III-Speed") {
			
			n = 1024;
			row = 135;
			column = 2;
			cumulativeDistributedTable = CumulativeDistributedTable.CUMULATIVE_DISTRIBUTED_TABLE_III_SPEED;
			
		} else if (parameterSet == "qTESLA-III-Size") {
			
			n = 1024;
			row = 101;
			column = 2;
			cumulativeDistributedTable = CumulativeDistributedTable.CUMULATIVE_DISTRIBUTED_TABLE_III_SIZE;
			
		} else if (parameterSet == "qTESLA-P-I") {
			
			n = 1024;
			row = 79;
			column = 1;
			cumulativeDistributedTable = CumulativeDistributedTable.CUMULATIVE_DISTRIBUTED_TABLE_P_I;
			
		} else if (parameterSet == "qTESLA-P-III") {
			
			n = 2048;
			row = 112;
			column = 2;
			cumulativeDistributedTable = CumulativeDistributedTable.CUMULATIVE_DISTRIBUTED_TABLE_P_III;
			
		} else {
			
			n = 1;
			row = 1;
			column = 1;
			cumulativeDistributedTable = null;
			
		}
		
	}
	
	private static void differ (long[] difference, long[] array, int u, int v, int position) {
		
		difference[0] = (difference[0] + (array[v + position] & Long.MAX_VALUE) - (array[u + position] & Long.MAX_VALUE)) >> 63;
		
	}
	
	private static void swap (long[] exchange, long[] difference, long[] array, int u, int v, int position) {
		
		exchange[0]			= (array[u + position] ^ array[v + position]) & difference[0];
		array[u + position]	^= exchange[0];
		array[v + position]	^= exchange[0];
		
	}
	
	private static void swapOrder (int[] exchange, long[] difference, int[] order, int u, int v) {
		
		exchange[0]	= (order[u] ^ order[v]) & (int) difference[0];
		order[u]	^= exchange[0];
		order[v]	^= exchange[0];
		
	}
	
	private static void minimumMaximum1 (long[] exchange, long[] difference, long[] array, int u, int v) {
		
		differ (difference, array, u, v, 0);
		swap (exchange, difference, array, u, v, 0);
		
	}
	
	private static void minimumMaximum2 (long[] exchange, long[] difference, long[] array, int u, int v) {
		
		if (column > 1) {
			
			differ (difference, array, u, v, 1);
			minimumMaximum1 (exchange, difference, array, u, v);
			swap (exchange, difference, array, u, v, 1);
			
		} else {
			
			minimumMaximum1 (exchange, difference, array, u, v);
			
		}
		
	}
	
	private static void minimumMaximum3 (long[] exchange, long[] difference, long[] array, int u, int v) {
		
		if (column > 2) {
			
			differ (difference, array, u, v, 2);
			minimumMaximum2 (exchange, difference, array, u, v);
			swap (exchange, difference, array, u, v, 2);
			
		} else {
			
			minimumMaximum2 (exchange, difference, array, u, v);
			
		}
		
	}
	
	private static void minimumMaximum4 (long[] exchange, long[] difference, long[] array, int u, int v) {
		
		if (column > 3) {
		
			differ (difference, array, u, v, 3);
			minimumMaximum3 (exchange, difference, array, u, v);
			swap (exchange, difference, array, u, v, 3);
		
		} else {
			
			minimumMaximum3 (exchange, difference, array, u, v);
			
		}
		
	}
	
	private static void minimumMaximum5 (long[] exchange, long[] difference, long[] array, int u, int v) {
		
		if (column > 4) {
		
			differ (difference, array, u, v, 4);
			minimumMaximum4 (exchange, difference, array, u, v);
			swap (exchange, difference, array, u, v, 4);
			
		} else {
			
			minimumMaximum4 (exchange, difference, array, u, v);
			
		}
		
	}
	
	private static void minimumMaximum (long[] array, int uArray, int vArray, int[] order, int uOrder, int vOrder) {
		
		if (column <= 5) {
			
			long[] difference		= {0};
			long[] exchangeArray	= {0};
			int[] exchangeOrder		= {0};
			
			minimumMaximum5 (exchangeArray, difference, array, uArray, vArray);
			swapOrder (exchangeOrder, difference, order, uOrder, vOrder);
			
		}
		
	}
	
	private static void minimumMaximumOrder (int[] order, int u, int v) {
		
		int difference	= ((order[v] & 0x7FFFFFFF) - (order[u] & 0x7FFFFFFF)) >> 31;
		int exchange	= (order[u] ^ order[v]) & difference;
		order[u]		^= exchange;
		order[v]		^= exchange;
		
	}
	
	/**********************************************************************************************
	 * Description: Sort the Key Order Array Using Donald Ervin Knuth's Iterative Merge-Exchange
	 *				Sorting.
	 * 
	 * @param	key			The Sampling Key Array to Sort in Place
	 * @param	order		The Accompanying Sampling Order Array to Sort Together
	 * @param	size		The Size of the Array
	 * 
	 * @return
	 **********************************************************************************************/
	private static void donaldErvinKnuthMergeExchangeKeyOrder (long[] key, int[] order, int size) {
		
		int counter = 1;
		
		while (counter < size - counter) {
			
			counter += counter;
			
		}
		
		for (int p = counter; p > 0; p >>>= 1) {
			
			int position	= 0;
			int positionP	= p * column;
			
			for (int i = 0; i < size - p; i++, position += column, positionP += column) {
				
				if ((i & p) == 0) {
					
					minimumMaximum (key, position, positionP, order, i, p + i);
					
				}
				
			}
			
			for (int q = counter; q > p; q >>>= 1) {
				
				positionP		= p * column;
				int positionQ	= q * column;
				
				for (int i = 0; i < size - q; i++, positionP += column, positionQ += column) {
					
					if ((i & p) == 0) {
						
						minimumMaximum (key, positionP, positionQ, order, p + i, q + i);
						
					}
					
				}
				
			}
			
		}
		
	}
	
	/*******************************************************************************
	 * Description: Sort the Sampling Order Array Using Donald Ervin Knuth's
	 * 				Iterative Merge-Exchange Sorting.
	 * 
	 * @param	order		The Accompanying Sampling Order Array to Sort Together
	 * @param	size		The Size of the Array
	 * 
	 * @return
	 *******************************************************************************/
	private static void donaldErvinKnuthMergeExchangeOrder (int[] order, int size) {
		
		int counter = 1;
		
		while (counter < size - counter) {
			
			counter += counter;
			
		}
		
		for (int p = counter; p > 0; p >>>= 1) {
			
			for (int i = 0; i < size - p; i++) {
				
				if ((i & p) == 0) {
					
					minimumMaximumOrder (order, i, p + i);
					
				}
				
			}
			
			for (int q = counter; q > p; q >>>= 1) {
				
				for (int i = 0; i < size - q; i++) {
					
					if ((i & p) == 0) {
						
						minimumMaximumOrder (order, p + i, q + i);
						
					}
					
				}
				
			}
			
		}
		
	}
	
	/**********************************************************************************************************
	 * Description: Generate CHUNK Samples from the Normal Distribution in Constant Time for Heuristic qTESLA
	 * 
	 * @param		data							Data to be Sampled
	 * @param		dataOffset						Starting Point of the Data to be Sampled
	 * @param		seed							Kappa-Bit Seed
	 * @param		seedOffset						Starting Point of the Kappa-Bit Seed
	 * @param		nonce							Domain Separator for Error Polynomial and Secret Polynomial	
	 * 
	 * @return
	 **********************************************************************************************************/
	private static void donaldErvinKnuthMergeExchangeGauss (
			
		int[] data, int dataOffset, byte[] seed, int seedOffset, int nonce
	
	) {
		
		long[] samplingKeyArray		= new long[(CHUNK + row) * column];
		byte[] samplingKeyByteArray	= new byte[(CHUNK + row) * column * Byte.SIZE];
		int[] samplingOrderArray	= new int[CHUNK + row];
		
		if (column == 1) {
			
			FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (		
				
				samplingKeyByteArray, 0, CHUNK * column * Long.SIZE / Byte.SIZE,
				(short) nonce,
				seed, seedOffset, QTESLAParameter.RANDOM					
			
			);
			
		} else {
			
			FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK256Simple (		
				
				samplingKeyByteArray, 0, CHUNK * column * Long.SIZE / Byte.SIZE,
				(short) nonce,
				seed, seedOffset, QTESLAParameter.RANDOM					
			
			);
			
		}
		
		Common.load64 (samplingKeyByteArray, samplingKeyArray);
				
		System.arraycopy (cumulativeDistributedTable, 0, samplingKeyArray, CHUNK * column, row * column);
		
		/* Keep Track of Each Entry's Sampling Order */
		for (int i = 0; i < CHUNK; i++) {
			
			samplingOrderArray[i] = i << 16;
			
		}
		
		/* Append the Cumulative Distributed Table Gaussian Indices (Prefixed with A Sentinel) */
		for (int i = 0; i < row; i++) {
			
			samplingOrderArray[CHUNK + i] = 0xFFFF0000 ^ i;
			
		}
		
		/* Constant-Time Sorting According to the Uniformly Random Sorting Key */
		donaldErvinKnuthMergeExchangeKeyOrder (samplingKeyArray, samplingOrderArray, CHUNK + row);
		
		/* Set Each Entry's Gaussian Index */
		int previousIndex = 0;
		
		for (int i = 0; i < CHUNK + row; i++) {
			
			int currentIndex = samplingOrderArray[i] & 0x0000FFFF;
			
			previousIndex ^= (currentIndex ^ previousIndex) & ((previousIndex - currentIndex) >> 31);
			
			/* Only the Unused Most Significant Bit of the Leading Word */
			int negative = (int) (samplingKeyArray[column * i] >> 63);
			
			samplingOrderArray[i] |= ((negative & -previousIndex) ^ (~ negative & previousIndex)) & 0x0000FFFF;
			
		}
		
		/* Sort All Index Entries According to Their Sampling Order as Sorting Key */
		donaldErvinKnuthMergeExchangeOrder (samplingOrderArray, CHUNK + row);
				
		/* Discard the Trailing Entries (Corresponding to the Cumulative Distributed Table) and Sample the Signs */
		for (int i = 0; i < CHUNK; i++) {
			
			data[dataOffset + i] = (samplingOrderArray[i] << 16) >> 16;
			
		}
		
	}
	
	/**************************************************************************************************************
	 * Description: Generate CHUNK Samples from the Normal Distribution in Constant Time for Provably Secure qTESLA
	 * 
	 * @param		data							Data to be Sampled
	 * @param		dataOffset						Starting Point of the Data to be Sampled
	 * @param		seed							Kappa-Bit Seed
	 * @param		seedOffset						Starting Point of the Kappa-Bit Seed
	 * @param		nonce							Domain Separator for Error Polynomial and Secret Polynomial		
	 * 
	 * @return
	 ***************************************************************************************************************/
	private static void donaldErvinKnuthMergeExchangeGauss_MB (
			
			int[] data, int dataOffset, byte[] seed, int seedOffset, int nonce
		
		) {
			final int mask = 2147483647;
			final int CHUNK_SIZE = CHUNK;
			final int CDT_ROWS = 111;
			final int CDT_COLS = 4;
			final int RADIX32 = 32;
			
			int[] samplingKeyArray		= new int[CHUNK_SIZE*CDT_COLS];
			byte[] samplingKeyByteArray	= new byte[(CHUNK_SIZE*CDT_COLS) * Integer.SIZE/Byte.SIZE];
			
			if (column == 1) {
				
				/*FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (		
					
					samplingKeyByteArray, 0, CHUNK * column * Long.SIZE / Byte.SIZE,
					(short) nonce,
					seed, seedOffset, QTESLAParameter.RANDOM					
				
				);*/
				System.out.println("column == 1");
				System.exit(3);
				
			} else {
				
				// This is in C: cSHAKE((uint8_t *)samp, CHUNK_SIZE*CDT_COLS*sizeof(int32_t), (int16_t)dmsp++, seed, CRYPTO_RANDOMBYTES);
				FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK256Simple (						
					samplingKeyByteArray, 0, CHUNK * column * Long.SIZE / Byte.SIZE,
					(short) nonce,
					seed, seedOffset, QTESLAParameter.RANDOM			
				);
				
			}		
			
			// Convert the bytes to int
			for(int i=0; i<samplingKeyByteArray.length; i+=4) {
				int temp =  ((samplingKeyByteArray[i+0] & 0xFF) << 0) | 
				            ((samplingKeyByteArray[i+1] & 0xFF) << 8) | 
				            ((samplingKeyByteArray[i+2] & 0xFF) << 16 ) | 
				            ((samplingKeyByteArray[i+3] & 0xFF) << 24 );
				samplingKeyArray[ i/4 ] = temp;
			}
			//Common.load64 (samplingKeyByteArray, samplingKeyArray);
			
			int borrow;
			int sign;
			int[] c = new int[CDT_COLS];
			//int[] samp = new int[CHUNK_SIZE*CDT_COLS];
			
			for (int i = 0; i < CHUNK_SIZE; i++) {
				data[dataOffset + i] = 0;
				
				for (int j = 1; j < CDT_ROWS; j++) {
					borrow = 0;
					
					for (int k = CDT_COLS-1; k >= 0; k--) {
						
						c[k] = (samplingKeyArray[i*CDT_COLS+k] & mask) 
								- (cumulativeDistributedTable_MB[j*CDT_COLS+k] + borrow);
						
						borrow = c[k] >> (RADIX32-1);
					}
					data[ dataOffset + i ] += ~borrow & 1;
				}
				sign = samplingKeyArray[i*CDT_COLS] >> (RADIX32-1); 
				data[dataOffset + i] = (sign & -data[ dataOffset + i ]) | (~sign & data [ dataOffset + i ] );
			}
			
			int stop=1;
			
			
			/*Common.load64 (samplingKeyByteArray, samplingKeyArray);
			
			System.arraycopy (cumulativeDistributedTable, 0, samplingKeyArray, CHUNK * column, row * column);
			
			// Keep Track of Each Entry's Sampling Order
			for (int i = 0; i < CHUNK; i++) {				
				samplingOrderArray[i] = i << 16;				
			}
			
			// Append the Cumulative Distributed Table Gaussian Indices (Prefixed with A Sentinel) 
			for (int i = 0; i < row; i++) {
				
				samplingOrderArray[CHUNK + i] = 0xFFFF0000 ^ i;
				
			}
			
			// Constant-Time Sorting According to the Uniformly Random Sorting Key
			donaldErvinKnuthMergeExchangeKeyOrder (samplingKeyArray, samplingOrderArray, CHUNK + row);
			
			// Set Each Entry's Gaussian Index
			int previousIndex = 0;
			
			for (int i = 0; i < CHUNK + row; i++) {
				
				int currentIndex = samplingOrderArray[i] & 0x0000FFFF;
				
				previousIndex ^= (currentIndex ^ previousIndex) & ((previousIndex - currentIndex) >> 31);
				
				// Only the Unused Most Significant Bit of the Leading Word
				int negative = (int) (samplingKeyArray[column * i] >> 63);
				
				samplingOrderArray[i] |= ((negative & -previousIndex) ^ (~ negative & previousIndex)) & 0x0000FFFF;
				
			}
			
			// Sort All Index Entries According to Their Sampling Order as Sorting Key
			donaldErvinKnuthMergeExchangeOrder (samplingOrderArray, CHUNK + row);
			
			// Discard the Trailing Entries (Corresponding to the Cumulative Distributed Table) and Sample the Signs 
			for (int i = 0; i < CHUNK; i++) {
				
				// vorher long!
				data[dataOffset + i] = (int) ((samplingOrderArray[i] << 16) >> 16);
				
			}*/
			
		}
	
	private static void donaldErvinKnuthMergeExchangeGauss (
			
		long[] data, int dataOffset, byte[] seed, int seedOffset, int nonce
	
	) {
		
		long[] samplingKeyArray		= new long[(CHUNK + row) * column];
		byte[] samplingKeyByteArray	= new byte[(CHUNK + row) * column * Byte.SIZE];
		int[] samplingOrderArray	= new int[CHUNK + row];
		
		if (column == 1) {
			
			FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (		
				
				samplingKeyByteArray, 0, CHUNK * column * Long.SIZE / Byte.SIZE,
				(short) nonce,
				seed, seedOffset, QTESLAParameter.RANDOM					
			
			);
			
		} else {
			
			FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK256Simple (		
				
				samplingKeyByteArray, 0, CHUNK * column * Long.SIZE / Byte.SIZE,
				(short) nonce,
				seed, seedOffset, QTESLAParameter.RANDOM					
			
			);
			
		}
		
		Common.load64 (samplingKeyByteArray, samplingKeyArray);
		
		System.arraycopy (cumulativeDistributedTable, 0, samplingKeyArray, CHUNK * column, row * column);
		
		/* Keep Track of Each Entry's Sampling Order */
		for (int i = 0; i < CHUNK; i++) {
			
			samplingOrderArray[i] = i << 16;
			
		}
		
		/* Append the Cumulative Distributed Table Gaussian Indices (Prefixed with A Sentinel) */
		for (int i = 0; i < row; i++) {
			
			samplingOrderArray[CHUNK + i] = 0xFFFF0000 ^ i;
			
		}
		
		/* Constant-Time Sorting According to the Uniformly Random Sorting Key */
		donaldErvinKnuthMergeExchangeKeyOrder (samplingKeyArray, samplingOrderArray, CHUNK + row);
		
		/* Set Each Entry's Gaussian Index */
		int previousIndex = 0;
		
		for (int i = 0; i < CHUNK + row; i++) {
			
			int currentIndex = samplingOrderArray[i] & 0x0000FFFF;
			
			previousIndex ^= (currentIndex ^ previousIndex) & ((previousIndex - currentIndex) >> 31);
			
			/* Only the Unused Most Significant Bit of the Leading Word */
			int negative = (int) (samplingKeyArray[column * i] >> 63);
			
			samplingOrderArray[i] |= ((negative & -previousIndex) ^ (~ negative & previousIndex)) & 0x0000FFFF;
			
		}
		
		/* Sort All Index Entries According to Their Sampling Order as Sorting Key */
		donaldErvinKnuthMergeExchangeOrder (samplingOrderArray, CHUNK + row);
		
		/* Discard the Trailing Entries (Corresponding to the Cumulative Distributed Table) and Sample the Signs */
		for (int i = 0; i < CHUNK; i++) {
			
			data[dataOffset + i] = (long) ((samplingOrderArray[i] << 16) >> 16);
			
		}
		
	}
	
	/*****************************************************************************************************************
	 * Description:	Gaussian Sampler for Heuristic qTESLA
	 * 
	 * @param		data						Data to be Sampled
	 * @param		dataOffset					Starting Point of the Data to be Sampled
	 * @param		seed						Kappa-Bit Seed
	 * @param		seedOffset					Starting Point of the Kappa-Bit Seed
	 * @param		nonce						Domain Separator for Error Polynomial and Secret Polynomial
	 * 
	 * @return		none
	 *****************************************************************************************************************/
	public void polynomialGaussianSampler (int[] data, int dataOffset, final byte[] seed, int seedOffset, int nonce) {
		
		int domainSeparator = nonce << 8;
		
		for (int chunk = 0; chunk < n; chunk += CHUNK) {
			
			donaldErvinKnuthMergeExchangeGauss (data, dataOffset + chunk, seed, seedOffset, domainSeparator++);
			
		}
		
	}
	
	/******************************************************************************************************************
	 * Description:	Gaussian Sampler for for Provably Secure qTESLA
	 * 
	 * @param		data						Data to be Sampled
	 * @param		dataOffset					Starting Point of the Data to be Sampled
	 * @param		seed						Kappa-Bit Seed
	 * @param		seedOffset					Starting Point of the Kappa-Bit Seed
	 * @param		nonce						Domain Separator for Error Polynomial and Secret Polynomial
	 * 
	 * @return		none
	 ******************************************************************************************************************/
	public void polynomialGaussianSampler_MB (int[] data, int dataOffset, final byte[] seed, int seedOffset, int nonce) {
		
		int domainSeparator = nonce << 8;		
		for (int chunk = 0; chunk < n; chunk += CHUNK) {	
			donaldErvinKnuthMergeExchangeGauss_MB (data, dataOffset + chunk, seed, seedOffset, domainSeparator++);	
		}

	}
	
	public void polynomialGaussianSampler (long[] data, int dataOffset, final byte[] seed, int seedOffset, int nonce) {
		
		int domainSeparator = nonce << 8;
		
		for (int chunk = 0; chunk < n; chunk += CHUNK) {
			
			donaldErvinKnuthMergeExchangeGauss (data, dataOffset + chunk, seed, seedOffset, domainSeparator++);
			
		}
		
	}

}