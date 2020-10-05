/************************************************************************************
* qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
*
* Secure-Hash-Algorithm 3 Derived Functions: Secure-Hash-Algorithm-and-KECCAK (SHAKE)
* and Customizable-Secure-Hash-Algorithm-and-KECCAK (cSHAKE)
* 
* See National Institute of Science and Technology Special Publication 800-185
* by John Kesley, Shu-jen Chang and Ray Perlner
* from Federal Information Processing Standards Publications 202
* 
* Link: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
* 
* @author Yinhua Xu
*************************************************************************************/

package sctudarmstadt.qtesla.java;
import java.util.Arrays;

public class FederalInformationProcessingStandard202 {
	
	public static final int SECURE_HASH_ALGORITHM_KECCAK_128_RATE = 168;
	public static final int SECURE_HASH_ALGORITHM_KECCAK_256_RATE = 136;
	public static final int SECURE_HASH_ALGORITHM_3_256_RATE = 136;
	public static final int NUMBER_OF_ROUND = 24;
	
	public static final long[] KECCAK_F_ROUND_CONSTANT = {
			
			0x0000000000000001L,	0x0000000000008082L,	0x800000000000808AL,	0x8000000080008000L,
			0x000000000000808BL,	0x0000000080000001L,	0x8000000080008081L,	0x8000000000008009L,
			0x000000000000008AL,	0x0000000000000088L,	0x0000000080008009L,	0x000000008000000AL,
			0x000000008000808BL,	0x800000000000008BL,	0x8000000000008089L,	0x8000000000008003L,
			0x8000000000008002L,	0x8000000000000080L,	0x000000000000800AL,	0x800000008000000AL,
			0x8000000080008081L,	0x8000000000008080L,	0x0000000080000001L,	0x8000000080008008L
			
	};
	
	private static void keccakF1600StatePermution (long[] state) {
	
		long[] C = new long[5];
		long[] D = new long[5];
		long[] E = new long[25];
		
		for (int round = 0; round < NUMBER_OF_ROUND; round += 2) {
			
			C[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
			C[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
			C[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
			C[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
			C[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];
			
			D[0] = C[4] ^ Long.rotateLeft (C[1], 1);
			D[1] = C[0] ^ Long.rotateLeft (C[2], 1);
			D[2] = C[1] ^ Long.rotateLeft (C[3], 1);
			D[3] = C[2] ^ Long.rotateLeft (C[4], 1);
			D[4] = C[3] ^ Long.rotateLeft (C[0], 1);
		
			state[ 0] ^= D[0];
			C[0] = state[0];
			state[ 6] ^= D[1];
			C[1] = Long.rotateLeft (state[ 6], 44);
			state[12] ^= D[2];
			C[2] = Long.rotateLeft (state[12], 43);
			state[18] ^= D[3];
			C[3] = Long.rotateLeft (state[18], 21);
			state[24] ^= D[4];
			C[4] = Long.rotateLeft (state[24], 14);
			
			E[ 0] = C[0] ^ ((~C[1]) & C[2]);
			E[ 0] ^= KECCAK_F_ROUND_CONSTANT[round];
			E[ 1] = C[1] ^ ((~C[2]) & C[3]);
			E[ 2] = C[2] ^ ((~C[3]) & C[4]);
			E[ 3] = C[3] ^ ((~C[4]) & C[0]);
			E[ 4] = C[4] ^ ((~C[0]) & C[1]);
			
			state[ 3] ^= D[3];
			C[0] = Long.rotateLeft (state[ 3], 28);
			state[ 9] ^= D[4];
			C[1] = Long.rotateLeft (state[ 9], 20);
			state[10] ^= D[0];
			C[2] = Long.rotateLeft (state[10],  3);
			state[16] ^= D[1];
			C[3] = Long.rotateLeft (state[16], 45);
			state[22] ^= D[2];
			C[4] = Long.rotateLeft (state[22], 61);
			
			E[ 5] = C[0] ^ ((~C[1]) & C[2]);
			E[ 6] = C[1] ^ ((~C[2]) & C[3]);
			E[ 7] = C[2] ^ ((~C[3]) & C[4]);
			E[ 8] = C[3] ^ ((~C[4]) & C[0]);
			E[ 9] = C[4] ^ ((~C[0]) & C[1]);
			
			state[ 1] ^= D[1];
			C[0] = Long.rotateLeft (state[ 1],  1);
			state[ 7] ^= D[2];
			C[1] = Long.rotateLeft (state[ 7],  6);
			state[13] ^= D[3];
			C[2] = Long.rotateLeft (state[13], 25);
			state[19] ^= D[4];
			C[3] = Long.rotateLeft (state[19],  8);
			state[20] ^= D[0];
			C[4] = Long.rotateLeft (state[20], 18);
			
			E[10] = C[0] ^ ((~C[1]) & C[2]);
			E[11] = C[1] ^ ((~C[2]) & C[3]);
			E[12] = C[2] ^ ((~C[3]) & C[4]);
			E[13] = C[3] ^ ((~C[4]) & C[0]);
			E[14] = C[4] ^ ((~C[0]) & C[1]);
			
			state[ 4] ^= D[4];
			C[0] = Long.rotateLeft (state[ 4], 27);
			state[ 5] ^= D[0];
			C[1] = Long.rotateLeft (state[ 5], 36);
			state[11] ^= D[1];
			C[2] = Long.rotateLeft (state[11], 10);
			state[17] ^= D[2];
			C[3] = Long.rotateLeft (state[17], 15);
			state[23] ^= D[3];
			C[4] = Long.rotateLeft (state[23], 56);
			
			E[15] = C[0] ^ ((~C[1]) & C[2]);
			E[16] = C[1] ^ ((~C[2]) & C[3]);
			E[17] = C[2] ^ ((~C[3]) & C[4]);
			E[18] = C[3] ^ ((~C[4]) & C[0]);
			E[19] = C[4] ^ ((~C[0]) & C[1]);
			
			state[ 2] ^= D[2];
			C[0] = Long.rotateLeft (state[ 2], 62);
			state[ 8] ^= D[3];
			C[1] = Long.rotateLeft (state[ 8], 55);
			state[14] ^= D[4];
			C[2] = Long.rotateLeft (state[14], 39);
			state[15] ^= D[0];
			C[3] = Long.rotateLeft (state[15], 41);
			state[21] ^= D[1];
			C[4] = Long.rotateLeft (state[21],  2);
			
			E[20] = C[0] ^ ((~C[1]) & C[2]);
			E[21] = C[1] ^ ((~C[2]) & C[3]);
			E[22] = C[2] ^ ((~C[3]) & C[4]);
			E[23] = C[3] ^ ((~C[4]) & C[0]);
			E[24] = C[4] ^ ((~C[0]) & C[1]);
			
			C[0] = E[0] ^ E[5] ^ E[10] ^ E[15] ^ E[20];
			C[1] = E[1] ^ E[6] ^ E[11] ^ E[16] ^ E[21];
			C[2] = E[2] ^ E[7] ^ E[12] ^ E[17] ^ E[22];
			C[3] = E[3] ^ E[8] ^ E[13] ^ E[18] ^ E[23];
			C[4] = E[4] ^ E[9] ^ E[14] ^ E[19] ^ E[24];
			
			D[0] = C[4] ^ Long.rotateLeft (C[1], 1);
			D[1] = C[0] ^ Long.rotateLeft (C[2], 1);
			D[2] = C[1] ^ Long.rotateLeft (C[3], 1);
			D[3] = C[2] ^ Long.rotateLeft (C[4], 1);
			D[4] = C[3] ^ Long.rotateLeft (C[0], 1);
			
			E[ 0] ^= D[0];
			C[0] = E[0];
			E[ 6] ^= D[1];
			C[1] = Long.rotateLeft (E[ 6], 44);
			E[12] ^= D[2];
			C[2] = Long.rotateLeft (E[12], 43);
			E[18] ^= D[3];
			C[3] = Long.rotateLeft (E[18], 21);
			E[24] ^= D[4];
			C[4] = Long.rotateLeft (E[24], 14);
			
			state[ 0] = C[0] ^ ((~C[1]) & C[2]);
			state[ 0] ^= KECCAK_F_ROUND_CONSTANT[round + 1];
			state[ 1] = C[1] ^ ((~C[2]) & C[3]);
			state[ 2] = C[2] ^ ((~C[3]) & C[4]);
			state[ 3] = C[3] ^ ((~C[4]) & C[0]);
			state[ 4] = C[4] ^ ((~C[0]) & C[1]);
			
			E[ 3] ^= D[3];
			C[0] = Long.rotateLeft (E[ 3], 28);
			E[ 9] ^= D[4];
			C[1] = Long.rotateLeft (E[ 9], 20);
			E[10] ^= D[0];
			C[2] = Long.rotateLeft (E[10],  3);
			E[16] ^= D[1];
			C[3] = Long.rotateLeft (E[16], 45);
			E[22] ^= D[2];
			C[4] = Long.rotateLeft (E[22], 61);
			
			state[ 5] = C[0] ^ ((~C[1]) & C[2]);
			state[ 6] = C[1] ^ ((~C[2]) & C[3]);
			state[ 7] = C[2] ^ ((~C[3]) & C[4]);
			state[ 8] = C[3] ^ ((~C[4]) & C[0]);
			state[ 9] = C[4] ^ ((~C[0]) & C[1]);
			
			E[ 1] ^= D[1];
			C[0] = Long.rotateLeft (E[ 1],  1);
			E[ 7] ^= D[2];
			C[1] = Long.rotateLeft (E[ 7],  6);
			E[13] ^= D[3];
			C[2] = Long.rotateLeft (E[13], 25);
			E[19] ^= D[4];
			C[3] = Long.rotateLeft (E[19],  8);
			E[20] ^= D[0];
			C[4] = Long.rotateLeft (E[20], 18);
			
			state[10] = C[0] ^ ((~C[1]) & C[2]);
			state[11] = C[1] ^ ((~C[2]) & C[3]);
			state[12] = C[2] ^ ((~C[3]) & C[4]);
			state[13] = C[3] ^ ((~C[4]) & C[0]);
			state[14] = C[4] ^ ((~C[0]) & C[1]);
			
			E[ 4] ^= D[4];
			C[0] = Long.rotateLeft (E[ 4], 27);
			E[ 5] ^= D[0];
			C[1] = Long.rotateLeft (E[ 5], 36);
			E[11] ^= D[1];
			C[2] = Long.rotateLeft (E[11], 10);
			E[17] ^= D[2];
			C[3] = Long.rotateLeft (E[17], 15);
			E[23] ^= D[3];
			C[4] = Long.rotateLeft (E[23], 56);
			
			state[15] = C[0] ^ ((~C[1]) & C[2]);
			state[16] = C[1] ^ ((~C[2]) & C[3]);
			state[17] = C[2] ^ ((~C[3]) & C[4]);
			state[18] = C[3] ^ ((~C[4]) & C[0]);
			state[19] = C[4] ^ ((~C[0]) & C[1]);
			
			E[ 2] ^= D[2];
			C[0] = Long.rotateLeft (E[ 2], 62);
			E[ 8] ^= D[3];
			C[1] = Long.rotateLeft (E[ 8], 55);
			E[14] ^= D[4];
			C[2] = Long.rotateLeft (E[14], 39);
			E[15] ^= D[0];
			C[3] = Long.rotateLeft (E[15], 41);
			E[21] ^= D[1];
			C[4] = Long.rotateLeft (E[21],  2);
			
			state[20] = C[0] ^ ((~C[1]) & C[2]);
			state[21] = C[1] ^ ((~C[2]) & C[3]);
			state[22] = C[2] ^ ((~C[3]) & C[4]);
			state[23] = C[3] ^ ((~C[4]) & C[0]);
			state[24] = C[4] ^ ((~C[0]) & C[1]);
			
		}

	}
	
	/*********************************************************************************************************
	 * Description: Absorption Phase of Secure Hash Algorithm and KECCAK
	 *********************************************************************************************************/
	private static void keccakAbsorb (
			
			long[] state, int rate, final byte[] message, int messageOffset, int messageLength, byte character
	
	) {
		
		byte[] T = new byte[200];
		
		while (messageLength >= rate) {
			
			for (int i = 0; i < rate / 8; ++i) {
				state[i] ^= Common.load64_MB (message, messageOffset + (Long.SIZE / Byte.SIZE) * i);
				
			}
			
			keccakF1600StatePermution (state);
			
			messageLength -= rate;
			messageOffset += rate;			
			
		}
		
		Arrays.fill (T, 0, rate, (byte) 0);
		
		System.arraycopy (message, messageOffset, T, 0, messageLength);
		
		T[messageLength] = character;
		T[rate - 1] |= 128;
		
		for (int i = 0; i < rate / (Long.SIZE / Byte.SIZE); ++i) {
			
			state[i] ^= Common.load64 (T, Long.SIZE / Byte.SIZE * i);
			
		}
		
	}
	
	/********************************************************************************************************************
	 * Description: Squeeze Phase of Secure Hash Algorithm and KECCAK
	 ********************************************************************************************************************/
	private static void keccakSqueezeBlock (byte[] output, int outputOffset, int numberOfBlock, long state[], int rate) {
		
		while (numberOfBlock > 0) {
			
			keccakF1600StatePermution (state);
			
			for (int i = 0; i < (rate >> 3); i++) {
				
				Common.store64 (output, outputOffset + Long.SIZE / Byte.SIZE * i, state[i]);
				
			}		

			outputOffset += rate;
			numberOfBlock--;
			
		}
	}
	
	/******************************************************************************************************************
	 * Description: Absorption Phase of Secure Hash Algorithm and KECCAK (128-Bit)
	 ******************************************************************************************************************/
	
	public static void secureHashAlgorithmKECCAK128Absorb (
			
		long[] state, final byte[] input, int inputOffset, int byteLengthOfInput
	
	) {
		
		keccakAbsorb (state, SECURE_HASH_ALGORITHM_KECCAK_128_RATE, input, inputOffset, byteLengthOfInput, (byte) 0x1F);
		
	}
	
	/******************************************************************************************************************
	 * Description: Absorption Phase of Secure Hash Algorithm and KECCAK (256-Bit)
	 ******************************************************************************************************************/
	public static void secureHashAlgorithmKECCAK256Absorb (
			
		long[] state, final byte[] input, int inputOffset, int byteLengthOfInput
	
	) {
		
		keccakAbsorb (state, SECURE_HASH_ALGORITHM_KECCAK_256_RATE, input, inputOffset, byteLengthOfInput, (byte) 0x1F);
		
	}
	
	/**********************************************************************************************************
	 * Description: Squeeze Phase of Secure Hash Algorithm and KECCAK (128-Bit)
	 **********************************************************************************************************/
	public static void secureHashAlgorithmKECCAK128SqueezeBlock (
			
		byte[] output, int outputOffset, int numberOfBlock, long[] state
			
	) {
		
		keccakSqueezeBlock (output, outputOffset, numberOfBlock, state, SECURE_HASH_ALGORITHM_KECCAK_128_RATE);
		
	}
	
	/**********************************************************************************************************
	 * Description: Squeeze Phase of Secure Hash Algorithm and KECCAK (256-Bit)
	 **********************************************************************************************************/
	public static void secureHashAlgorithmKECCAK256SqueezeBlock (
			
		byte[] output, int outputOffset, int numberOfBlock, long[] state
			
	) {
		
		keccakSqueezeBlock (output, outputOffset, numberOfBlock, state, SECURE_HASH_ALGORITHM_KECCAK_256_RATE);
		
	}
	
	/***************************************************************************
	 * Description: Secure Hash Algorithm and KECCAK Extendable-Output Function
	 ***************************************************************************/
	private static void secureHashAlgorithmKECCAK (
			
			byte[] output, int outputOffset, int outputLength,
			final byte[] input, int inputOffset, int inputLength, int rate
			
	) {
		
		long[] state = new long[25];
		byte[] T = new byte[rate];
		int numberOfBlock = outputLength / rate;
		
		Arrays.fill (state, 0L);
		
		/* Absorb input */
		keccakAbsorb (state, rate, input, inputOffset, inputLength, (byte) 0x1F);
		
		/* Squeeze output */
		keccakSqueezeBlock (output, outputOffset, numberOfBlock, state, rate);
		
		outputOffset += numberOfBlock * rate;
		outputLength -= numberOfBlock * rate;
		
		if (outputLength > 0) {
			
			keccakSqueezeBlock (T, 0, 1, state, rate);
			
			for (int i = 0; i < outputLength; i++) {				
				output[outputOffset + i] = T[i];				
			}			
		}
		//System.exit(13);
		
	}
	
	/*****************************************************************************************************************
	 * Description:	The Secure-Hash-Algorithm-3 Extendable-Output Function That Generally Supports 128 Bits of
	 *				Security Strength, If the Output is Sufficiently Long
	 *****************************************************************************************************************/
	public static void secureHashAlgorithmKECCAK128 (
			
		byte[] output, int outputOffset, int outputLength, byte[] input, int inputOffset, int inputLength
			
	) {
		
		secureHashAlgorithmKECCAK (
				
			output, outputOffset, outputLength, input, inputOffset, inputLength, SECURE_HASH_ALGORITHM_KECCAK_128_RATE
				
		);
		
	}
	
	/*****************************************************************************************************************
	 * Description:	The Secure-Hash-Algorithm-3 Extendable-Output Function That Generally Supports 256 Bits of
	 *				Security Strength, If the Output is Sufficiently Long
	 *****************************************************************************************************************/
	public static void secureHashAlgorithmKECCAK256 (
			
		byte[] output, int outputOffset, int outputLength, byte[] input, int inputOffset, int inputLength
			
	) {
		
		secureHashAlgorithmKECCAK (
				
			output, outputOffset, outputLength, input, inputOffset, inputLength, SECURE_HASH_ALGORITHM_KECCAK_256_RATE
		
		);
		
	}
	
	/********************************************************************************
	 * Description: Absorption Phase of Customizable Secure Hash Algorithm and KECCAK
	 ********************************************************************************/
	 
	private static void customizableSecureHashAlgorithmKECCAKSimpleAbsorb (
			
		long[] state, short continuousTimeStochasticModelling,
		byte[] input, int inputOffset, int inputLength,
		long firstState, int rate
			
	) {
		
		Arrays.fill(state, 0L);
		
		/* Absorb Customization (Domain-Separation) String */
		state[0] = firstState; 
		state[0] ^= (long) continuousTimeStochasticModelling << 48;
		
		keccakF1600StatePermution (state);
		
		/* Absorb Input */
		keccakAbsorb (state, rate, input, inputOffset, inputLength, (byte) 4);
		
	}
	
	/********************************************************************************************************
	 * Description: Absorption Phase of Customizable Secure Hash Algorithm and KECCAK (128-Bit)
	 ********************************************************************************************************/
	public static void customizableSecureHashAlgorithmKECCAK128SimpleAbsorb (
			
		long[] state, short continuousTimeStochasticModelling, byte[] input, int inputOffset, int inputLength
	
	) {
		
		customizableSecureHashAlgorithmKECCAKSimpleAbsorb (
				
			state, continuousTimeStochasticModelling,
			input, inputOffset, inputLength,
			(long) 0x10010001A801L, SECURE_HASH_ALGORITHM_KECCAK_128_RATE
				
		);
		
	}
	
	/********************************************************************************************************
	 * Description: Absorption Phase of Customizable Secure Hash Algorithm and KECCAK (256-Bit)
	 ********************************************************************************************************/
	public static void customizableSecureHashAlgorithmKECCAK256SimpleAbsorb (
			
		long[] state, short continuousTimeStochasticModelling, byte[] input, int inputOffset, int inputLength
		
	) {
		
		customizableSecureHashAlgorithmKECCAKSimpleAbsorb (
				
			state, continuousTimeStochasticModelling,
			input, inputOffset, inputLength,
			(long) 0x100100018801L, SECURE_HASH_ALGORITHM_KECCAK_256_RATE
				
		);
		
	}
	
	/**********************************************************************************************************
	 * Description: Squeeze Phase of Customizable Secure Hash Algorithm and KECCAK (128-Bit)
	 **********************************************************************************************************/
	public static void customizableSecureHashAlgorithmKECCAK128SimpleSqueezeBlock (
			
		byte[] output, int outputOffset, int numberOfBlock, long[] state
			
	) {

		keccakSqueezeBlock (output, outputOffset, numberOfBlock, state, SECURE_HASH_ALGORITHM_KECCAK_128_RATE);
		
	}
	
	/**********************************************************************************************************
	 * Description: Squeeze Phase of Customizable Secure Hash Algorithm and KECCAK (256-Bit)
	 **********************************************************************************************************/
	public static void customizableSecureHashAlgorithmKECCAK256SimpleSqueezeBlock (
			
		byte[] output, int outputOffset, int numberOfBlock, long[] state
			
	) {
		
		keccakSqueezeBlock (output, outputOffset, numberOfBlock, state, SECURE_HASH_ALGORITHM_KECCAK_256_RATE);
		
	}
	
	private static void customizableSecureHashAlgorithmKECCAKSimple (
			
		byte[] output, int outputOffset, int outputLength,
		short continuousTimeStochasticModelling,
		byte[] input, int inputOffset, int inputLength,
		long firstState, int rate
			
	) {
		
		long state[] = new long[25];
		byte T[] = new byte[rate];
		
		customizableSecureHashAlgorithmKECCAKSimpleAbsorb (				
			state, continuousTimeStochasticModelling, input, inputOffset, inputLength, firstState, rate				
		);
		
		/* Squeeze output */
		keccakSqueezeBlock (output, outputOffset, outputLength / rate, state, rate);		
		outputOffset += (outputLength / rate) * rate;
		
		if (outputLength % rate != 0) {			
			keccakSqueezeBlock (T, 0, 1, state, rate);			
			for (int i = 0; i < outputLength % rate; i++) {				
				output[outputOffset + i] = T[i];				
			}		
		}	
	}
	
	public static void customizableSecureHashAlgorithmKECCAK128Simple (
			
		byte[] output, int outputOffset, int outputLength,
		short continuousTimeStochasticModelling,
		byte[] input, int inputOffset, int inputLength
			
	) {
		
		customizableSecureHashAlgorithmKECCAKSimple (
				
			output, outputOffset, outputLength,
			continuousTimeStochasticModelling,
			input, inputOffset, inputLength,
			(long) 0x10010001A801L, SECURE_HASH_ALGORITHM_KECCAK_128_RATE
			
		);
		
	}
	
	public static void customizableSecureHashAlgorithmKECCAK256Simple (
			
		byte[] output, int outputOffset, int outputLength,
		short continuousTimeStochasticModelling,
		byte[] input, int inputOffset, int inputLength
	
	) {
		
		customizableSecureHashAlgorithmKECCAKSimple (
				
			output, outputOffset, outputLength,
			continuousTimeStochasticModelling,
			input, inputOffset, inputLength,
			(long) 0x100100018801L, SECURE_HASH_ALGORITHM_KECCAK_256_RATE
			
		);
		
	}
	
}