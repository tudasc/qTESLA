/****************************************************************************************************
* qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
*
* Functions of qTESLA Signature Scheme (Key Generation, Signature Generation, Signature Verification)
* 
* @author Yinhua Xu
*****************************************************************************************************/

package qTESLA;

import java.util.ArrayList;

import javax.crypto.BadPaddingException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

public class QTESLA {
	
	private static SigningThread winner = null;
	
	private static QTESLAParameter parameter;
	
	private static QTESLAPack qTESLAPack;
	
	private static Polynomial polynomial;
	
	private static QTESLAYSampler qTESLAYSampler;
	
	private static QTESLAGaussianSampler qTESLAGaussianSampler;
	
	private static RandomNumberGenerator randomNumberGenerator;
	
	/*******************************************************************
	 * qTESLA Constructor
	 * 
	 * @param parameterSet		qTESLA Parameter Set
	 *******************************************************************/
	public QTESLA (String parameterSet) {
		
		parameter = new QTESLAParameter (parameterSet);
		qTESLAPack = new QTESLAPack (parameterSet);
		polynomial = new Polynomial (parameterSet);
		qTESLAYSampler = new QTESLAYSampler (parameterSet);
		qTESLAGaussianSampler = new QTESLAGaussianSampler (parameterSet);
		randomNumberGenerator = new RandomNumberGenerator ();
	}
	
	/*********************************************
	 * Getter of qTESLA Parameter Object
	 * 
	 * @return	none
	 *********************************************/
	public QTESLAParameter getQTESLAParameter () {
		
		return parameter;
		
	}
	
	/***********************************
	 * Getter of Polynomial Object
	 * 
	 * @return	none
	 ***********************************/
	public Polynomial getPolynomial () {
		
		return polynomial;
		
	}
	
	/*********************************************************
	 * Getter of Random Number Generator Object
	 * 
	 * @return	none
	 *********************************************************/
	public RandomNumberGenerator getRandomNumberGenerator () {
		
		return randomNumberGenerator;
		
	}
	
	/*********************************************************************************************************************
	 * Description:	Hash-Based Function to Generate C' for Heuristic qTESLA
	 *********************************************************************************************************************/
	private static void hashFunction_MB (byte[] output, int[] V, final byte[] message, int off) {
		
		byte[] T = new byte[parameter.n * parameter.k + 2 * parameter.h];
		int mask;
		int cL;
		int temp;		
		int index; 
		
		for (int k=0; k < parameter.k; k++) {
			index = k*parameter.n;
			
			for (int i = 0; i < parameter.n; i++) {
				temp = (int)V[index];
				
				// If V[i] > Q / 2 Then V[i] = V[i] - Q
				mask = (parameter.q / 2 - temp) >> (32-1);				
				temp = ((temp-parameter.q) & mask) | (temp & ~mask);

				cL = temp & ((1 << parameter.d) - 1);			
				
				// If cL > 2 ^ (d - 1) Then cL = cL - 2 ^ d
				mask = ((1<<(parameter.d-1)) - cL) >> (32-1);  
				cL = ((cL-(1<<parameter.d)) & mask) | (cL & ~mask); 
				T[index++] = (byte) ((temp - cL) >> parameter.d);				
			}
		}
		
		System.arraycopy(message, off, T, parameter.k * parameter.n, 2* parameter.h);	
		
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (				
			output, 0/* off*/, QTESLAParameter.HASH, T, 0, parameter.k * parameter.n + 2*parameter.h/*QTESLAParameter.MESSAGE*/);
	}
	
	/**********************************************************************************************************************
	 * Description:	Hash Function to Generate C' for Provably Secure qTESLA
	 **********************************************************************************************************************/
	private static void hashFunction (byte[] output, int outputOffset, long[] V, final byte[] message, int messageOffset) {
		
		int index;
		int mask;
		int cL;
		int temporary;
		
		byte[] T = new byte[parameter.n * parameter.k + QTESLAParameter.MESSAGE];
		
		for (int j = 0; j < parameter.k; j++) {			
			index = parameter.n * j;
			
			for (int i = 0; i < parameter.n; i++) {
				
				temporary	= (int) V[index];
				
				/* If V[i] > Q / 2 Then V[i] = V[i] - Q */
				mask		= (parameter.q / 2 - temporary) >> 31;//63;
				System.out.print("[" + index + "]" + mask + "/" + temporary + " ");
			
				temporary	= ((temporary - parameter.q) & mask) | (temporary & (~ mask));
				cL			= temporary & ((1 << parameter.d) - 1);
				/* If cL > 2 ^ (d - 1) Then cL = cL - 2 ^ d */
				mask		= ((1 << (parameter.d - 1)) - cL) >> 31;
				cL			= ((cL - (1 << parameter.d)) & mask) | (cL & (~ mask));
				T[index++]	= (byte) ((temporary - cL) >> parameter.d);
				
			}
			
		}
		
		System.arraycopy (message, messageOffset, T, parameter.n * parameter.k, QTESLAParameter.MESSAGE);
		
		if (parameter.parameterSet == "qTESLA-P-I") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (				
				output, outputOffset, QTESLAParameter.HASH, T, 0, parameter.n * parameter.k + QTESLAParameter.MESSAGE
			
			);
		
		}
		
		if (parameter.parameterSet == "qTESLA-P-III") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
				
				output, outputOffset, QTESLAParameter.HASH, T, 0, parameter.n * parameter.k + QTESLAParameter.MESSAGE
			
			);
			
		}
	
	}
	
	private static void hashFunction (byte[] output, int outputOffset, int[] V, final byte[] message, int messageOffset) {
		
		int mask;
		int cL;
		
		byte[] T = new byte[parameter.n + QTESLAParameter.MESSAGE];
		
		for (int i = 0; i < parameter.n; i++) {
			/* If V[i] > Q / 2 Then V[i] = V[i] - Q */
			mask	= (parameter.q / 2 - V[i]) >> 31;
			V[i]	= ((V[i] - parameter.q) & mask) | (V[i] & (~ mask));
			cL		= V[i] & ((1 << parameter.d) - 1);
			/* If cL > 2 ^ (d - 1) Then cL = cL - 2 ^ d */
			mask	= ((1 << (parameter.d - 1)) - cL) >> 31;
			cL		= ((cL - (1 << parameter.d)) & mask) | (cL & (~ mask));
			T[i]	= (byte) ((V[i] - cL) >> parameter.d);
			
		}
		
		System.arraycopy (message, messageOffset, T, parameter.n, QTESLAParameter.MESSAGE);
		
		if (parameter.parameterSet == "qTESLA-I") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (
				
				output, outputOffset, QTESLAParameter.HASH, T, 0, parameter.n + QTESLAParameter.MESSAGE
			
			);
		
		}
		
		if (parameter.parameterSet == "qTESLA-III-Speed" || parameter.parameterSet == "qTESLA-III-Size") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
				
				output, outputOffset, QTESLAParameter.HASH, T, 0, parameter.n + QTESLAParameter.MESSAGE
			
			);
			
		}
		
	}
	
	/**************************************************************************************************************
	 * Description:	Encoding of C' by Mapping the Output of the Hash Function H to An N-Element Vector with
	 * 				Entries {-1, 0, 1}
	 * 
	 * @param		postionList			{0, ..., n - 1} ^ h
	 * @param		signList			{-1, +1} ^ h
	 * @param		output				Result of the Hash Function H
	 * @param		outputOffset		Starting Point of the Result of the Hash Function H
	 * 
	 * @return		none
	 **************************************************************************************************************/
	public void encodeC (int[] positionList, short[] signList, byte[] output, int outputOffset) {
		
		int count = 0;
		int position;
		short domainSeparator = 0;
		short[] C = new short[parameter.n];
		byte[] randomness = new byte[FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE];
		
		/* Use the Hash Value as Key to Generate Some Randomness */
		FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (
			
			randomness, 0, FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE,
			domainSeparator++,
			output, outputOffset, QTESLAParameter.RANDOM
		
		);
		
		/* Use Rejection Sampling to Determine Positions to be Set in the New Vector */
		Arrays.fill (C, 0, parameter.n, (short) 0);
		
		/* Sample A Unique Position k times.
		 * Use Two Bytes
		 */
		for (int i = 0; i < parameter.h;) {
			
			if (count > FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE - 3) {
				
				FederalInformationProcessingStandard202.customizableSecureHashAlgorithmKECCAK128Simple (
					
					randomness, 0, FederalInformationProcessingStandard202.SECURE_HASH_ALGORITHM_KECCAK_128_RATE,
					domainSeparator++,
					output, outputOffset, QTESLAParameter.RANDOM
				
				);
				
				count = 0;
				
			}
			
			position = (randomness[count] << 8) | (randomness[count + 1] & 0xFF);
			position &= (parameter.n - 1);
				
			/* Position is between [0, n - 1] and Has not Been Set Yet
			 * Determine Signature
			 */
			if (C[position] == 0) {
				
				if ((randomness[count + 2] & 1) == 1) {
						
					C[position] = -1;
						
				} else {
						
					C[position] = 1;
						
				}
					
				positionList[i] = position;
				signList[i] = C[position];
				i++;
					
			}
			
			count += 3;
			
		}
		
	}

	
	/*************************************************************************
	 * Description:	Checks Bounds for Signature Vector Z During Signification.
	 * 				Leaks the Position of the Coefficient that Fails the Test.
	 * 				The Position of the Coefficient is Independent of the
	 * 				Secret Data.
	 * 				Does not Leak the Signature of the Coefficients.
	 * 				Heuristic qTESLA
	 * 
	 * @param		Z		Signature Vector
	 * 
	 * @return		false	Valid / Accepted
	 * 				true	Invalid / Rejected
	 *************************************************************************/
	private static boolean testRejection (int[] Z) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			if (Common.absolute (Z[i]) > (parameter.b - parameter.boundS)) {
				
				return true;
				
			}
			
		}
		
		return false;
		
	}
	
	/*****************************************************************************
	 * Description:	Checks Bounds for Signature Vector Z During Signification.
	 * 				Leaks the Position of the Coefficient that Fails the Test.
	 * 				The Position of the Coefficient is Independent of the
	 *				Secret Data.
	 * 				Does not Leak the Signature of the Coefficients.
	 * 				Provably-Secure qTESLA
	 * 
	 * @param		Z		Signature Vector
	 * 
	 * @return		false	Valid / Accepted
	 * 				true	Invalid / Rejected
	 *****************************************************************************/
	private static boolean testRejection (long[] Z) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			if (Common.absolute ((int) Z[i]) > (parameter.b - parameter.boundS)) {
				
				return true;
				
			}
			
		}
		
		return false;
		
	}
	
	/******************************************************************************************************
	 * Description:	Checks Bounds for Signature Vector Z During Signature Verification for Heuristic qTESLA
	 * 
	 * @param		Z		Signature Vector
	 * 
	 * @return		false	Valid / Accepted
	 * 				true	Invalid / Rejected
	 ******************************************************************************************************/
	private static boolean testZ (int[] Z) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			if ((Z[i] < - (parameter.b - parameter.boundS)) || (Z[i] > parameter.b - parameter.boundS)) {
				
				return true;
				
			}
			
		}
		
		return false;
		
	}
	
	/****************************************************************************************************
	 * Description:	Checks Bounds for Signature Vector Z During Signature Verification for
	 *				Provably Secure qTESLA
	 * 
	 * @param		Z		Signature Vector
	 * 
	 * @return		false	Valid / Accepted
	 * 				true	Invalid / Rejected
	 ****************************************************************************************************/
	private static boolean testZ (long[] Z) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			if ((Z[i] < - (parameter.b - parameter.boundS)) || (Z[i] > parameter.b - parameter.boundS)) {
				
				return true;
				
			}
			
		}
		
		return false;
		
	}
	
	/**************************************************************************************************
	 * Description:	Checks Bounds for W = V - EC During Signature Verification.
	 * 				Leaks the Position of the Coefficient that Fails the Test.
	 * 				The Position of the Coefficient is Independent of the Secret Data.
	 * 				Does not Leak the Signature of the Coefficients.
	 * 				Heuristic qTESLA
	 * 
	 * @param		V			Parameter to be Checked
	 * 
	 * @return		false		Valid / Accepted
	 * 				true		Invalid / Rejected
	 **************************************************************************************************/
	private static boolean testCorrectness (int[] V) {
	
		int mask;
		int left;
		int right;
		int test1;
		int test2;
		
		for (int i = 0; i < parameter.n; i++) {
			
			mask  = (parameter.q / 2 - V[i]) >> 31;
			right = ((V[i] - parameter.q) & mask) | (V[i] & (~ mask));
			test1 = (~ (Common.absolute (right) - (parameter.q / 2 - parameter.boundE))) >>> 31;
			left  = right;
			right = (right + (1 << (parameter.d - 1)) - 1) >> parameter.d;
			right = left - (right << parameter.d);
			test2 = (~ (Common.absolute (right) - ((1 << (parameter.d - 1)) - parameter.boundE))) >>> 31;
			
			/* Two Tests Fail */
			if ((test1 | test2) == 1) {
				
				return true;
				
			}
			
		}
		
		return false;
		
	}
	
	/**************************************************************************************************
	 * Description:	Checks Bounds for W = V - EC During Signature Verification.
	 * 				Leaks the Position of the Coefficient that Fails the Test.
	 * 				The Position of the Coefficient is Independent of the Secret Data.
	 * 				Does not Leak the Signature of the Coefficients.
	 * 				Provably-Secure qTESLA
	 * 
	 * @param		V			Parameter to be Checked
	 * @param		vOffset		Starting Point of V
	 * 
	 * @return		false		Valid / Accepted
	 * 				true		Invalid / Rejected
	 ***************************************************************************************************/
	private static boolean testCorrectness_MB (int[] V, int vOffset) {
		
		int mask;
		int left;
		int right;
		int test1;
		int test2;
		
		for (int i = 0; i < parameter.n; i++) {
			
			mask  = (int) (parameter.q / 2 - V[vOffset + i]) >> 31;
			right = (int) (((V[vOffset + i] - parameter.q) & mask) | (V[vOffset + i] & (~ mask)));
			test1 = (~ (Common.absolute (right) - (parameter.q / 2 - parameter.boundE))) >>> 31;
			
			left  = right;
			right = (right + (1 << (parameter.d - 1)) - 1) >> parameter.d;
			right = left - (right << parameter.d);
			test2 = (~ (Common.absolute (right) - ((1 << (parameter.d - 1)) - parameter.boundE))) >>> 31;
			
			/* Two Tests Fail */
			if ((test1 | test2) == 1L) {
				
				return true;
				
			}
			
		}
		
		return false;
		
	}
	
	private static boolean testCorrectness (long[] V, int vOffset) {
	
		int mask;
		int left;
		int right;
		int test1;
		int test2;
		
		for (int i = 0; i < parameter.n; i++) {
			
			mask  = (int) (parameter.q / 2 - V[vOffset + i]) >> 31;
			right = (int) (((V[vOffset + i] - parameter.q) & mask) | (V[vOffset + i] & (~ mask)));
			test1 = (~ (Common.absolute (right) - (parameter.q / 2 - parameter.boundE))) >>> 31;
			
			left  = right;
			right = (right + (1 << (parameter.d - 1)) - 1) >> parameter.d;
			right = left - (right << parameter.d);
			test2 = (~ (Common.absolute (right) - ((1 << (parameter.d - 1)) - parameter.boundE))) >>> 31;
			
			/* Two Tests Fail */
			if ((test1 | test2) == 1L) {
				
				return true;
				
			}
			
		}
		
		return false;
		
	}
	
	/*********************************************************************
	 * Description:	Checks Whether the Generated Error Polynomial or
	 * 				the Generated Secret Polynomial Fulfills
	 *				Certain Properties Needed in Key Generation Algorithm
	 *				for Heuristic qTESLA
	 * 
	 * @param		polynomial		Parameter to be Checked
	 * @param		bound			Threshold of Summation
	 * 
	 * @return		false			Fulfillment
	 * 				true			No Fulfillment
	 *********************************************************************/
	private static boolean checkPolynomial (int[] polynomial, int bound) {
		
		long summation = 0;
		int limit = parameter.n;
		int temporary;
		int mask;
		int[] list = new int[parameter.n];
		
		for (int i = 0; i < parameter.n; i++) {
			
			list[i] = Common.absolute (polynomial[i]);
			
		}
		
		for (int i = 0; i < parameter.h; i++) {
			
			for (int j = 0; j < limit - 1; j++) {
				/* If list[j + 1] > list[j] Then Exchanges Contents */
				mask		= (list[j + 1] - list[j]) >> 31;
				temporary	= (list[j + 1] & mask) | (list[j]     & (~ mask));
				list[j + 1]	= (list[j]     & mask) | (list[j + 1] & (~ mask));
				list[j]		= temporary;
				
			}
			
			summation += list[limit - 1];
			
			limit--;
			
		}
		
		if (summation > bound) {
			
			return true;
			
		}
		
		return false;
		
	}
	
	/**********************************************************************************
	 * Description:	Checks Whether the Generated Error Polynomial or the Generated
	 * 				Secret Polynomial Fulfills Certain Properties Needed in
	 *				Key Generation Algorithm for Provably-Secure qTESLA
	 * 
	 * @param		polynomial		Parameter to be Checked
	 * @param		offset			Starting Point of the Polynomial to be Checked
	 * @param		bound			Threshold of Summation
	 * 
	 * @return		false			Fulfillment
	 * 				true			No Fulfillment
	 **********************************************************************************/
	private static boolean checkPolynomial_MB (int[] polynomial, int offset, int bound) {
		
		int summation = 0;
		int limit = parameter.n;
		int temporary;
		int mask;
		int[] list = new int[parameter.n];
		
		for (int i = 0; i < parameter.n; i++) {
			
			list[i] = Common.absolute ((int) polynomial[offset + i]);
			
		}
		
		for (int i = 0; i < parameter.h; i++) {
			
			for (int j = 0; j < limit - 1; j++) {
				/* If list[j + 1] > list[j] Then Exchanges Contents */
				mask		= (list[j + 1] - list[j]) >> 31;
				temporary	= (list[j + 1] & mask) | (list[j]	  & (~ mask));
				list[j + 1]	= (list[j]     & mask) | (list[j + 1] & (~ mask));
				list[j]		= temporary;
				
			}
			
			summation += list[limit - 1];
			limit--;
			
		}
		
		if (summation > bound) {
			
			return true;
			
		}
		
		return false;
		
	}	
	
	
	private static boolean checkPolynomial (long[] polynomial, int offset, int bound) {
		
		int summation = 0;
		int limit = parameter.n;
		int temporary;
		int mask;
		int[] list = new int[parameter.n];
		
		for (int i = 0; i < parameter.n; i++) {
			
			list[i] = Common.absolute ((int) polynomial[offset + i]);
			
		}
		
		for (int i = 0; i < parameter.h; i++) {
			
			for (int j = 0; j < limit - 1; j++) {
				/* If list[j + 1] > list[j] Then Exchanges Contents */
				mask		= (list[j + 1] - list[j]) >> 31;
				temporary	= (list[j + 1] & mask) | (list[j]	  & (~ mask));
				list[j + 1]	= (list[j]     & mask) | (list[j + 1] & (~ mask));
				list[j]		= temporary;
				
			}
			
			summation += list[limit - 1];
			limit--;
			
		}
		
		if (summation > bound) {
			
			return true;
			
		}
		
		return false;
		
	}
	
	/************************************************************************************************************************
	 * Description:	Generates A Pair of Public Key and Private Key for Heuristic qTESLA Signature Scheme
	 * 
	 * @param		publicKey							Contains Public Key
	 * @param		privateKey							Contains Private Key
	 * @param		secureRandom						Source of Randomness
	 * 
	 * @return		0									Successful Execution
	 * 
	 * @throws		BadPaddingException
	 * @throws		IllegalBlockSizeException
	 * @throws		InvalidKeyException
	 * @throws		NoSuchAlgorithmException
	 * @throws 		NoSuchPaddingException
	 * @throws		ShortBufferException
	 ************************************************************************************************************************/
	public int generateKeyPair (byte[] publicKey, byte[] privateKey, SecureRandom secureRandom) throws
		
		BadPaddingException,
		IllegalBlockSizeException,
		InvalidKeyException,
		NoSuchAlgorithmException,
		NoSuchPaddingException,
		ShortBufferException

	{
		
		/* Initialize Domain Separator for Error Polynomial and Secret Polynomial */
		int nonce = 0;
		
		byte[] randomness			= new byte[QTESLAParameter.RANDOM];
		
		/* Extend Random Bytes to Seed Generation of Error Polynomial and Secret Polynomial */
		byte[] randomnessExtended	= new byte[QTESLAParameter.SEED * 4];
		
		int[] secretPolynomial	= new int[parameter.n];
		int[] errorPolynomial	= new int[parameter.n];
		int[] A					= new int[parameter.n];
		int[] T					= new int[parameter.n];
		
		/* Get randomnessExtended <- seedErrorPolynomial, seedSecretPolynomial, seedA, seedY */
		randomNumberGenerator.randomByte (randomness, 0, QTESLAParameter.RANDOM);
		// secureRandom.nextBytes (randomness);
		
		if (parameter.parameterSet == "qTESLA-I") { 
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (
				
				randomnessExtended, 0, QTESLAParameter.SEED * 4, randomness, 0, QTESLAParameter.RANDOM
			
			);
			
		}
		
		if (parameter.parameterSet == "qTESLA-III-Speed" || parameter.parameterSet == "qTESLA-III-Size") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
				
				randomnessExtended, 0, QTESLAParameter.SEED * 4, randomness, 0, QTESLAParameter.RANDOM
			
			);
			
		}
		
		/* 
		 * Sample the Error Polynomial Fulfilling the Criteria 
		 * Choose All Error Polynomial in R with Entries from D_SIGMA
		 * Repeat Step at Iteration if the h Largest Entries of Error Polynomial Summation to L_E
		 */
		do {
			
			qTESLAGaussianSampler.polynomialGaussianSampler (errorPolynomial, 0, randomnessExtended, 0, ++nonce);
			
		} while (checkPolynomial (errorPolynomial, parameter.boundE) == true);
		
		/* 
		 * Sample the Secret Polynomial Fulfilling the Criteria 
		 * Choose Secret Polynomial in R with Entries from D_SIGMA
		 * Repeat Step if the h Largest Entries of Secret Polynomial Summation to L_S
		 */
		do {
			
			qTESLAGaussianSampler.polynomialGaussianSampler (secretPolynomial, 0, randomnessExtended, QTESLAParameter.SEED, ++nonce);
				
		} while (checkPolynomial (secretPolynomial, parameter.boundS) == true);
		
		/* Generate Uniform Polynomial A */
		polynomial.polynomialUniform (A, randomnessExtended, QTESLAParameter.SEED * 2);
		
		/* Compute the Public Key T = A * secretPolynomial + errorPolynomial */
		polynomial.polynomialMultiplication (T, A, secretPolynomial);
		polynomial.polynomialAdditionCorrection (T, T, errorPolynomial);
		
		/* Pack Public and Private Keys */
		qTESLAPack.encodePrivateKey (privateKey, secretPolynomial, errorPolynomial, randomnessExtended, QTESLAParameter.SEED * 2);
		qTESLAPack.encodePublicKey (publicKey, T, randomnessExtended, QTESLAParameter.SEED * 2);
		
		return 0;
		
	}
	
	/******************************************************************************************************************
	 * Description:	Generates A Pair of Public Key and Private Key for Provably Secure qTESLA Signature Scheme
	 * 
	 * @param		publicKey							Contains Public Key
	 * @param		privateKey							Contains Private Key
	 * @param		secureRandom						Source of Randomness	
	 * 
	 * @return		0									Successful Execution
	 * 
	 * @throws		BadPaddingException 
	 * @throws		IllegalBlockSizeException 
	 * @throws		InvalidKeyException
	 * @throws		NoSuchAlgorithmException 
	 * @throws		NoSuchPaddingException
	 * @throws		ShortBufferException
	 *****************************************************************************************************************/
	public int generateKeyPair_MB (byte[] publicKey, byte[] privateKey, SecureRandom secureRandom) throws

	BadPaddingException,
	IllegalBlockSizeException,
	InvalidKeyException,
	NoSuchAlgorithmException,
	NoSuchPaddingException,
	ShortBufferException

{
	
	/* Initialize Domain Separator for Error Polynomial and Secret Polynomial */
	int nonce = 0;
	
	byte[] randomness			= new byte[QTESLAParameter.RANDOM];
	
	/* Extend Random Bytes to Seed Generation of Error Polynomial and Secret Polynomial */
	byte[] randomnessExtended	= new byte[QTESLAParameter.SEED * (parameter.k + 3)];
	
	int[] secretPolynomial							= new int[parameter.n];
	int[] secretPolynomialNumberTheoreticTransform	= new int[parameter.n];
	int[] errorPolynomial							= new int[parameter.n * parameter.k];
	int[] A										= new int[parameter.n * parameter.k];
	int[] T										= new int[parameter.n * parameter.k];
	
	/* Get randomnessExtended <- seedErrorPolynomial, seedSecretPolynomial, seedA, seedY */
	randomNumberGenerator.randomByte (randomness, 0, QTESLAParameter.RANDOM);
	// secureRandom.nextBytes (randomness);
	
	//TMP
	 /* randomness[0]=-74;
	  randomness[1]=89;
	  randomness[2]=-62;
	  randomness[3]=18;
	  randomness[4]=106;
	  randomness[5]=-120;
	  randomness[6]=-47;
	  randomness[7]=-10;
	  randomness[8]=-96;
	  randomness[9]=89;
	  randomness[10]=9;
	  randomness[11]=48;
	  randomness[12]=33;
	  randomness[13]=94;
	  randomness[14]=-123;
	  randomness[15]=-83;
	  randomness[16]=41;
	  randomness[17]=-76;
	  randomness[18]=-109;
	  randomness[19]=111;
	  randomness[20]=-39;
	  randomness[21]=-93;
	  randomness[22]=61;
	  randomness[23]=79;
	  randomness[24]=60;
	  randomness[25]=33;
	  randomness[26]=47;
	  randomness[27]=-95;
	  randomness[28]=35;
	  randomness[29]=-118;
	  randomness[30]=8;
	  randomness[31]=-81;*/
	
	if (parameter.parameterSet == "qTESLA-P-I") {
		
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (			
			randomnessExtended, 0, QTESLAParameter.SEED * (parameter.k + 3), randomness, 0, QTESLAParameter.RANDOM		
		);
		
	}
	
	if (parameter.parameterSet == "qTESLA-P-III") {
		
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
			
			randomnessExtended, 0, QTESLAParameter.SEED * (parameter.k + 3), randomness, 0, QTESLAParameter.RANDOM
		
		);		
	}
	
	/* 
	 * Sample the Error Polynomial Fulfilling the Criteria 
	 * Choose All Error Polynomial_i in R with Entries from D_SIGMA
	 * Repeat Step at Iteration if the h Largest Entries of Error Polynomial_k Summation to L_E
	 */
	for (int i = 0; i < parameter.k; i++) {		
		do {			
			qTESLAGaussianSampler.polynomialGaussianSampler_MB (					
				errorPolynomial, parameter.n * i, randomnessExtended, QTESLAParameter.SEED * i, ++nonce				
			);			
		} while (checkPolynomial_MB (errorPolynomial, parameter.n * i, parameter.boundE) == true);
	
	}
	
	/* 
	 * Sample the Secret Polynomial Fulfilling the Criteria 
	 * Choose Secret Polynomial in R with Entries from D_SIGMA
	 * Repeat Step if the h Largest Entries of Secret Polynomial Summation to L_S
	 */
	do {
		
		qTESLAGaussianSampler.polynomialGaussianSampler_MB (				
			secretPolynomial, 0, randomnessExtended, QTESLAParameter.SEED * parameter.k, ++nonce			
		);
					
	} while (checkPolynomial_MB (secretPolynomial, 0, parameter.boundS) == true);
	
	/* Generate Uniform Polynomial A */
	polynomial.polynomialUniform_MB (A, randomnessExtended, QTESLAParameter.SEED * (parameter.k + 1));		
	polynomial.polynomialNumberTheoreticTransform_MB (secretPolynomialNumberTheoreticTransform, secretPolynomial);
	
	/* Compute the Public Key T = A * secretPolynomial + errorPolynomial */
	for (int i = 0; i < parameter.k; i++) {		
		polynomial.polynomialMultiplication_MB (				
			T, parameter.n * i, A, parameter.n * i, secretPolynomialNumberTheoreticTransform, 0			
		);	
		
		polynomial.polynomialAdditionCorrection_MB (				
			T, parameter.n * i, T, parameter.n * i, errorPolynomial, parameter.n * i			
		);	
	}
	
	qTESLAPack.encodePublicKey_MB (publicKey, T, randomnessExtended, QTESLAParameter.SEED * (parameter.k + 1));

	
	/* Pack Public and Private Keys */	
	byte[] hash_pk = new byte [parameter.h];	
	FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (			
			hash_pk, 0, parameter.h, 
			publicKey,  0, parameter.publicKeySize - QTESLAParameter.SEED				
		);
	
	qTESLAPack.encodePrivateKey_MB (privateKey, secretPolynomial, errorPolynomial, randomnessExtended, 
			(parameter.k + 1) * QTESLAParameter.SEED, hash_pk);	
	return 0;	
}
	
	
	public int generateKeyPairP (byte[] publicKey, byte[] privateKey, SecureRandom secureRandom) throws

		BadPaddingException,
		IllegalBlockSizeException,
		InvalidKeyException,
		NoSuchAlgorithmException,
		NoSuchPaddingException,
		ShortBufferException

	{
		
		/* Initialize Domain Separator for Error Polynomial and Secret Polynomial */
		int nonce = 0;
		
		byte[] randomness			= new byte[QTESLAParameter.RANDOM];
		
		/* Extend Random Bytes to Seed Generation of Error Polynomial and Secret Polynomial */
		byte[] randomnessExtended	= new byte[QTESLAParameter.SEED * (parameter.k + 3)];
		
		long[] secretPolynomial							= new long[parameter.n];
		long[] secretPolynomialNumberTheoreticTransform	= new long[parameter.n];
		long[] errorPolynomial							= new long[parameter.n * parameter.k];
		long[] A										= new long[parameter.n * parameter.k];
		long[] T										= new long[parameter.n * parameter.k];
		
		/* Get randomnessExtended <- seedErrorPolynomial, seedSecretPolynomial, seedA, seedY */
		randomNumberGenerator.randomByte (randomness, 0, QTESLAParameter.RANDOM);
		// secureRandom.nextBytes (randomness);
		
		if (parameter.parameterSet == "qTESLA-P-I") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (
				
				randomnessExtended, 0, QTESLAParameter.SEED * (parameter.k + 3), randomness, 0, QTESLAParameter.RANDOM
			
			);
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-III") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
				
				randomnessExtended, 0, QTESLAParameter.SEED * (parameter.k + 3), randomness, 0, QTESLAParameter.RANDOM
			
			);
			
		}
		
		/* 
		 * Sample the Error Polynomial Fulfilling the Criteria 
		 * Choose All Error Polynomial_i in R with Entries from D_SIGMA
		 * Repeat Step at Iteration if the h Largest Entries of Error Polynomial_k Summation to L_E
		 */
		for (int i = 0; i < parameter.k; i++) {
			
			do {
				
				qTESLAGaussianSampler.polynomialGaussianSampler (
						
					errorPolynomial, parameter.n * i, randomnessExtended, QTESLAParameter.SEED * i, ++nonce
					
				);
				
			} while (checkPolynomial (errorPolynomial, parameter.n * i, parameter.boundE) == true);
		
		}
		
		/* 
		 * Sample the Secret Polynomial Fulfilling the Criteria 
		 * Choose Secret Polynomial in R with Entries from D_SIGMA
		 * Repeat Step if the h Largest Entries of Secret Polynomial Summation to L_S
		 */
		do {
			
			qTESLAGaussianSampler.polynomialGaussianSampler (
					
				secretPolynomial, 0, randomnessExtended, QTESLAParameter.SEED * parameter.k, ++nonce
				
			);
						
		} while (checkPolynomial (secretPolynomial, 0, parameter.boundS) == true);
		
		/* Generate Uniform Polynomial A */
		polynomial.polynomialUniform (A, randomnessExtended, QTESLAParameter.SEED * (parameter.k + 1));
			
		polynomial.polynomialNumberTheoreticTransform (secretPolynomialNumberTheoreticTransform, secretPolynomial);
		
		/* Compute the Public Key T = A * secretPolynomial + errorPolynomial */
		for (int i = 0; i < parameter.k; i++) {
			
			polynomial.polynomialMultiplication (
					
				T, parameter.n * i, A, parameter.n * i, secretPolynomialNumberTheoreticTransform, 0
				
			);	
			
			polynomial.polynomialAdditionCorrection (
					
				T, parameter.n * i, T, parameter.n * i, errorPolynomial, parameter.n * i
				
			);
		
		}
		
		/* Pack Public and Private Keys */
		qTESLAPack.packPrivateKey (
				
			privateKey, secretPolynomial, errorPolynomial, randomnessExtended, QTESLAParameter.SEED * (parameter.k + 1)
			
		);
		
		qTESLAPack.encodePublicKey (publicKey, T, randomnessExtended, QTESLAParameter.SEED * (parameter.k + 1));
		
		return 0;
		
	}
	
	/**************************************************************************************************************
	 * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for
	 * 				Heuristic qTESLA
	 * 
	 * @param		message								Message to be Signed
	 * @param		messageOffset						Starting Point of the Message to be Signed
	 * @param		messageLength						Length of the Message to be Signed
	 * @param		signature							Output Package Containing Signature
	 * @param		signatureOffset						Starting Point of the Output Package Containing Signature
	 * @param		signatureLength						Length of the Output Package Containing Signature
	 * @param		privateKey							Private Key
	 * @param		secureRandom						Source of Randomness
	 * 
	 * @return		0									Successful Execution
	 * 
	 * @throws		BadPaddingException
	 * @throws		IllegalBlockSizeException
	 * @throws		InvalidKeyException
	 * @throws		NoSuchAlgorithmException
	 * @throws		NoSuchPaddingException 
	 * @throws		ShortBufferException
	 **************************************************************************************************************/
public int sign (
			
			byte[] signature, int signatureOffset, int[] signatureLength,
			final byte[] message, int messageOffset, int messageLength,
			final byte[] privateKey, SecureRandom secureRandom
			
	) throws 
	
		BadPaddingException,
		IllegalBlockSizeException,
		InvalidKeyException,
		NoSuchAlgorithmException,
		NoSuchPaddingException,
		ShortBufferException

	{
		
		byte[] C						= new byte[QTESLAParameter.HASH];
		byte[] randomness				= new byte[QTESLAParameter.SEED];
		byte[] randomnessInput			=
			new byte[QTESLAParameter.RANDOM + QTESLAParameter.SEED + QTESLAParameter.MESSAGE];
		byte[] seed						= new byte[QTESLAParameter.SEED * 2];
		// byte[] temporaryRandomnessInput	= new byte[Polynomial.RANDOM];
		int[] positionList				= new int[parameter.h];
		short[] signList				= new short[parameter.h];
		short[] secretPolynomial		= new short[parameter.n];
		short[] errorPolynomial			= new short[parameter.n];
		
		int[] A		= new int[parameter.n];
		int[] V		= new int[parameter.n];
		int[] Y		= new int[parameter.n];
		int[] Z		= new int[parameter.n];
		int[] SC	= new int[parameter.n];
		int[] EC	= new int[parameter.n];
		
		/* Domain Separator for Sampling Y */
		int nonce = 0;
		
		qTESLAPack.decodePrivateKey (seed, secretPolynomial, errorPolynomial, privateKey);
		
		randomNumberGenerator.randomByte (randomnessInput, QTESLAParameter.RANDOM, QTESLAParameter.RANDOM);
		// secureRandom.nextBytes (temporaryRandomnessInput);
		// System.arraycopy (temporaryRandomnessInput, 0, randomnessInput, Polynomial.RANDOM, Polynomial.RANDOM);
		
		System.arraycopy (seed, QTESLAParameter.SEED, randomnessInput, 0, QTESLAParameter.SEED);
		
		if (parameter.parameterSet == "qTESLA-I") {
		
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (
				
				randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED, QTESLAParameter.MESSAGE,
				message, 0, messageLength
			
			);
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (
				
				randomness, 0, QTESLAParameter.SEED,
				randomnessInput, 0, QTESLAParameter.RANDOM + QTESLAParameter.SEED + QTESLAParameter.MESSAGE
			
			);
		
		}
		
		if (parameter.parameterSet == "qTESLA-III-Speed" || parameter.parameterSet == "qTESLA-III-Size") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
				
				randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED, QTESLAParameter.MESSAGE,
				message, 0, messageLength
			
			);
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
				
				randomness, 0, QTESLAParameter.SEED,
				randomnessInput, 0, QTESLAParameter.RANDOM + QTESLAParameter.SEED + QTESLAParameter.MESSAGE
			
			);
			
		}
		
		//DeterministicValueReader.readR_IandR(randomnessInput, randomness);
		
		polynomial.polynomialUniform (A, seed, 0);
		//DeterministicValueReader.readA(A);
		
		/* Loop Due to Possible Rejection */
		while (true) {
			
			/* Sample Y Uniformly Random from -B to B */
			qTESLAYSampler.sampleY (Y, randomness, 0, ++nonce);		
			
			/* V = A * Y Modulo Q */
			polynomial.polynomialMultiplication (V, A, Y);
			
			hashFunction (C, 0, V, randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED);
			
			/* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
			encodeC (positionList, signList, C, 0);
			
			polynomial.sparsePolynomialMultiplication16 (SC, secretPolynomial, positionList, signList);
			
			/* Z = Y + EC Modulo Q */
			polynomial.polynomialAddition(Z, Y, SC);
			
			/* Rejection Sampling */
			if (testRejection (Z) == true) {
				
				continue;
				
			}
			
			polynomial.sparsePolynomialMultiplication16 (EC, errorPolynomial, positionList, signList);
			
			/* V = V - EC modulo Q */
			polynomial.polynomialSubtractionCorrection (V, V, EC);
			
			if (testCorrectness (V) == true) {
				
				continue;
				
			}
			
			/* Copy the Message into the Signature Package */
			System.arraycopy (
					
				message, messageOffset, signature, signatureOffset + parameter.signatureSize, messageLength
				
			);
				
			/* Length of the Output */
			signatureLength[0] = parameter.signatureSize + messageLength;
				
			/* Pack Signature */
			qTESLAPack.encodeSignature (signature, 0, C, 0, Z);
			
			return 0;
			
		}
		
	}
	

public int sign_MB (
		
		byte[] signature, int signatureOffset, int[] signatureLength,
		final byte[] message, int messageOffset, int messageLength,
		final byte[] privateKey, SecureRandom secureRandom

) throws
	
	BadPaddingException,
	IllegalBlockSizeException,
	InvalidKeyException,
	NoSuchAlgorithmException,
	NoSuchPaddingException,
	ShortBufferException

{
	byte[] C						= new byte[QTESLAParameter.HASH];
	byte[] randomness				= new byte[QTESLAParameter.SEED];
	byte[] randomnessInput			=
		new byte[144];
	byte[] seed						= new byte[QTESLAParameter.SEED * 2];
	// byte[] temporaryRandomnessInput	= new byte[Polynomial.RANDOM];
	int[] positionList				= new int[parameter.h];
	short[] signList				= new short[parameter.h];
	short[] secretPolynomial		= new short[parameter.n];
	short[] errorPolynomial			= new short[parameter.n];
	
	int[] Y		= new int[parameter.n];
	int[] Y_ntt		= new int[parameter.n];
	int[] SC	= new int[parameter.n];
	int[] Z		= new int[parameter.n];
	
	int[] V		= new int[parameter.n * parameter.k];	
	int[] EC	= new int[parameter.n * parameter.k];
	int[] A		= new int[parameter.n * parameter.k];	
	
	boolean response = false;
	
	/* Domain Separator for Sampling Y */
	int nonce = 0;
	//DeterministicValueReader.readR_IandR(randomnessInput, randomness);

	System.arraycopy (			
			privateKey, parameter.privateKeySize - parameter.h - QTESLAParameter.SEED, randomnessInput, 0, QTESLAParameter.SEED		
	);	

	randomNumberGenerator.randomByte (randomnessInput, QTESLAParameter.RANDOM, QTESLAParameter.RANDOM);
	
	FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (		
			randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED, 
			parameter.h,
			message, 0, messageLength	
		);	
		
	FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (		
			randomness, 0, QTESLAParameter.SEED,
			randomnessInput, 0, QTESLAParameter.RANDOM + QTESLAParameter.SEED + parameter.h
		);	
		
	System.arraycopy (			
				privateKey, parameter.privateKeySize - parameter.h, randomnessInput,
				QTESLAParameter.RANDOM + QTESLAParameter.RANDOM + parameter.h, parameter.h		
		);	
	
	polynomial.polynomialUniform_MB (A, privateKey, parameter.privateKeySize - parameter.h -2 * QTESLAParameter.SEED);	
	
	int cnt=0;
	while (true) {
		cnt++;
		qTESLAYSampler.sampleY_MB (Y, randomness, 0, ++nonce);		
		
		
		for(int g=0; g<Y_ntt.length; g++) Y_ntt[g]=0;
		polynomial.polynomialNumberTheoreticTransform_MB (Y_ntt, Y);		
		
		for(int g=0; g<V.length; g++) V[g]=0;
	    for (int k=0; k<parameter.k; k++) {
	    	polynomial.polynomialMultiplication_MB(V, k*parameter.n, A, k*parameter.n, Y_ntt, 0);
	    }	    
	    
	    for(int g=0; g<C.length; g++) C[g]=0;
	    hashFunction_MB (C, V, randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED);
	    
		/* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
		encodeC (positionList, signList, C, 0);
		
		for(int g=0; g<SC.length; g++) SC[g]=0;
		polynomial.sparsePolynomialMultiplication8_MB (SC, 0, privateKey, 0, positionList, signList);
		
		/* Z = Y + EC modulo Q */
		for(int g=0; g<Z.length; g++) Z[g]=0;
		polynomial.polynomialAddition_MB (Z, 0, Y, 0, SC, 0);
		
		/* Rejection Sampling */
		if (testRejection (Z) == true) {			
			continue;			
		}
		
		for(int g=0; g<EC.length; g++) EC[g]=0;
		for (int i = 0; i < parameter.k; i++) {
			
			polynomial.sparsePolynomialMultiplication8_MB (					
				EC, parameter.n * i, privateKey, parameter.n * (i + 1), positionList, signList				
			);
			
			/* V_i = V_i - EC_i Modulo Q for All k */
			polynomial.polynomialSubtraction_MB (V, parameter.n * i, V, parameter.n * i, EC, parameter.n * i);	
			
			response = testCorrectness_MB (V, parameter.n * i);
			
			if (response == true) {			
				break;				
			}
		}		
		
		if (response == true) {			
			continue;			
		}	
		
		/* Copy the Message into the Signature Package */
		System.arraycopy (				
			message, messageOffset, signature, signatureOffset + parameter.signatureSize, messageLength			
		);
			
		/* Length of the Output */
		signatureLength[0] = messageLength + parameter.signatureSize;
			
		/* Pack Signature */
		qTESLAPack.encodeSignature_MB (signature, 0, C, 0, Z);	
		
		// DBG-Output
		/*System.out.println("Y_ntt");
		for(int g=0; g<Y_ntt.length; g++) System.out.println(Y_ntt[g]);
		
		System.out.println("V");
		for(int g=0; g<V.length; g++) System.out.println(V[g]);
		
		System.out.println("C");
		for(int g=0; g<C.length; g++) System.out.println(C[g]);
		
		System.out.println("positionList");
		for(int g=0; g<positionList.length; g++) System.out.println(positionList[g]);
		
		System.out.println("positionList");
		for(int g=0; g<signList.length; g++) System.out.println(signList[g]);
		
		System.out.println("SC");
		for(int g=0; g<SC.length; g++) System.out.println(SC[g]);
		
		System.out.println("Z");
		for(int g=0; g<Z.length; g++) System.out.println(Z[g]);
		
		System.out.println("EC");
		for(int g=0; g<Z.length; g++) System.out.println(EC[g]);
		
		System.out.println("V");
		for(int g=0; g<V.length; g++) System.out.println(V[g]);
		
		System.out.println("signature");
		for(int g=0; g<signature.length; g++) System.out.println(signature[g]);*/

		//System.out.println("Required " + cnt);

		
		return 0;		
		
	}

}


	/*************************************************************************************************************
	 * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for
	 *				Provably Secure qTESLA
	 * 
	 * @param		message								Message to be Signed
	 * @param		messageOffset						Starting Point of the Message to be Signed
	 * @param		messageLength						Length of the Message to be Signed
	 * @param		signature							Output Package Containing Signature
	 * @param		signatureOffset						Starting Point of the Output Package Containing Signature
	 * @param		signatureLength						Length of the Output Package Containing Signature
	 * @param		privateKey							Private Key
	 * @param		secureRandom						Source of Randomness
	 * 
	 * @return		0									Successful Execution
	 * 
	 * @throws		BadPaddingException
	 * @throws		IllegalBlockSizeException
	 * @throws		InvalidKeyException
	 * @throws		NoSuchAlgorithmException
	 * @throws		NoSuchPaddingException
	 * @throws		ShortBufferException
	 *************************************************************************************************************/
public int signP (
		
		byte[] signature, int signatureOffset, int[] signatureLength,
		final byte[] message, int messageOffset, int messageLength,
		final byte[] privateKey, SecureRandom secureRandom

) throws
	
	BadPaddingException,
	IllegalBlockSizeException,
	InvalidKeyException,
	NoSuchAlgorithmException,
	NoSuchPaddingException,
	ShortBufferException

{
	
	byte[] C						= new byte[QTESLAParameter.HASH];
	byte[] randomness				= new byte[QTESLAParameter.SEED];
	byte[] randomnessInput			=
		new byte[QTESLAParameter.RANDOM + QTESLAParameter.SEED + QTESLAParameter.MESSAGE];
	// byte[] temporaryRandomnessInput	= new byte[Polynomial.RANDOM];
	int[] positionList				= new int[parameter.h];
	short[] signList				= new short[parameter.h];
	
	long[] A							= new long[parameter.n * parameter.k];
	long[] V							= new long[parameter.n * parameter.k];
	long[] Y							= new long[parameter.n];
	long[] numberTheoreticTransformY	= new long[parameter.n];
	long[] Z							= new long[parameter.n];
	long[] SC							= new long[parameter.n];
	long[] EC							= new long[parameter.n * parameter.k];
	
	boolean response = false;
	
	/* Domain Separator for Sampling Y */
	int nonce = 0;
	
	randomNumberGenerator.randomByte (randomnessInput, QTESLAParameter.RANDOM, QTESLAParameter.RANDOM);
	// secureRandom.nextBytes (temporaryRandomnessInput);
	// System.arraycopy (temporaryRandomnessInput, 0, randomnessInput, Polynomial.RANDOM, Polynomial.RANDOM);
	System.arraycopy (
			
		privateKey, parameter.privateKeySize - QTESLAParameter.SEED, randomnessInput, 0, QTESLAParameter.SEED
		
	);
	
	if (parameter.parameterSet == "qTESLA-P-I") {
	
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (
			
			randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED, QTESLAParameter.MESSAGE,
			message, 0, messageLength
		
		);
		
		
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (
			
			randomness, 0, QTESLAParameter.SEED,
			randomnessInput, 0, QTESLAParameter.RANDOM + QTESLAParameter.SEED + QTESLAParameter.MESSAGE
		
		);
	
	}
	
	if (parameter.parameterSet == "qTESLA-P-III") {
		
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
			
			randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED, QTESLAParameter.MESSAGE,
			message, 0, messageLength
		
		);
		
		
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
			
			randomness, 0, QTESLAParameter.SEED,
			randomnessInput, 0, QTESLAParameter.RANDOM + QTESLAParameter.SEED + QTESLAParameter.MESSAGE
		
		);
		
	}
	
	polynomial.polynomialUniform (A, privateKey, parameter.privateKeySize - 2 * QTESLAParameter.SEED);
	
	/* Loop Due to Possible Rejection */
	while (true) {
		
		/* Sample Y Uniformly Random from -B to B */
		qTESLAYSampler.sampleY (Y, randomness, 0, ++nonce);
		
		polynomial.polynomialNumberTheoreticTransform (numberTheoreticTransformY, Y);
		
		/* V_i = A_i * Y Modulo Q for All i */
		for (int i = 0; i < parameter.k; i++) {
			
			polynomial.polynomialMultiplication (
				
				V, parameter.n * i, A, parameter.n * i, numberTheoreticTransformY, 0
				
			);
			
		}
		
		hashFunction (C, 0, V, randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED);
		
		/* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
		encodeC (positionList, signList, C, 0);
		
		polynomial.sparsePolynomialMultiplication8 (SC, 0, privateKey, 0, positionList, signList);
		
		/* Z = Y + EC modulo Q */
		polynomial.polynomialAddition (Z, 0, Y, 0, SC, 0);
		
		/* Rejection Sampling */
		if (testRejection (Z) == true) {
			
			continue;
			
		}
		
		for (int i = 0; i < parameter.k; i++) {
			
			polynomial.sparsePolynomialMultiplication8 (
					
				EC, parameter.n * i, privateKey, parameter.n * (i + 1), positionList, signList
				
			);
			
			/* V_i = V_i - EC_i Modulo Q for All k */
			polynomial.polynomialSubtraction (V, parameter.n * i, V, parameter.n * i, EC, parameter.n * i);
			
			response = testCorrectness (V, parameter.n * i);
			
			if (response == true) {
			
				break;
				
			}
		
		}
		
		if (response == true) {
			
			continue;
			
		}
		
		/* Copy the Message into the Signature Package */
		System.arraycopy (
				
			message, messageOffset, signature, signatureOffset + parameter.signatureSize, messageLength
			
		);
			
		/* Length of the Output */
		signatureLength[0] = messageLength + parameter.signatureSize;
			
		/* Pack Signature */
		qTESLAPack.encodeSignature (signature, 0, C, 0, Z);
		
		return 0;
		
	}
	
}	
    //synchronized static void done()
	static void done()
    {
        // Threads calling this are going to be RaceHorse objects.
        // Now, if there isn't already a winner, this RaceHorse is the winner.
        if (winner == null) {
        	winner = (SigningThread) Thread.currentThread();
        	//System.out.println("Done() called by " + winner.getName());
        }
        
    }
	
	
	/*************************************************************************************************************
	 * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for
	 *				Provably Secure qTESLA
	 * 
	 * @param		message								Message to be Signed
	 * @param		messageOffset						Starting Point of the Message to be Signed
	 * @param		messageLength						Length of the Message to be Signed
	 * @param		signature							Output Package Containing Signature
	 * @param		signatureOffset						Starting Point of the Output Package Containing Signature
	 * @param		signatureLength						Length of the Output Package Containing Signature
	 * @param		privateKey							Private Key
	 * @param		secureRandom						Source of Randomness
	 * 
	 * @return		0									Successful Execution
	 * 
	 * @throws		BadPaddingException
	 * @throws		IllegalBlockSizeException
	 * @throws		InvalidKeyException
	 * @throws		NoSuchAlgorithmException
	 * @throws		NoSuchPaddingException
	 * @throws		ShortBufferException
	 * @throws InterruptedException 
	 *************************************************************************************************************/
	public int signPParallel (
			
			byte[] signature, int signatureOffset, int[] signatureLength,
			final byte[] message, int messageOffset, int messageLength,
			final byte[] privateKey, SecureRandom secureRandom
	
	) throws
		
		BadPaddingException,
		IllegalBlockSizeException,
		InvalidKeyException,
		NoSuchAlgorithmException,
		NoSuchPaddingException,
		ShortBufferException, 
		InterruptedException
	
	{		
		winner=null;
		final int number_threads = Logger.no_of_threads;
		CountDownLatch countDownLatch = new CountDownLatch(1);		
		ArrayList<SigningThread> threadies = new ArrayList<SigningThread>();

		for (int i=0; i<number_threads;i++) {			
			SigningThread t1 = new SigningThread(i, countDownLatch, privateKey, message, messageLength, 
					randomNumberGenerator, qTESLAYSampler, parameter, polynomial);
			threadies.add(
					t1
					);
			threadies.get(i).start();
		}
			
		/* Copy the Message into the Signature Package */
		System.arraycopy (				
			message, messageOffset, signature, signatureOffset + parameter.signatureSize, messageLength			
		);
			
		/* Length of the Output */
		signatureLength[0] = messageLength + parameter.signatureSize;
			
		countDownLatch.await(); 
		
		try {			
			qTESLAPack.encodeSignature_MB (signature, 0, winner.C, 0, winner.Z);
		}
		catch (NullPointerException e) {
			System.out.print("qTESLAPack.encodeSignature failed");
		}		
		
		//System.out.println("Signing finished by thread " + winner.getName());		
		return 0;		
	}
	
	
	/*****************************************************************************************************
	 * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for
	 *				A Given Signature Package for Heuristic qTESLA
	 * 
	 * @param 		signature							Given Signature Package
	 * @param		signatureOffset						Starting Point of the Given Signature Package
	 * @param		signatureLength						Length of the Given Signature Package
	 * @param		message								Original (Signed) Message
	 * @param		messageOffset						Starting Point of the Original (Signed) Message
	 * @param		messageLength						Length of the Original (Signed) Message
	 * @param		publicKey							Public Key
	 * 
	 * @return		0									Valid Signature
	 * 				< 0									Invalid Signature
	 *****************************************************************************************************/
	public int verify (
			
			byte[] message, int messageOffset, int[] messageLength,
			final byte[] signature, int signatureOffset, int signatureLength,
			final byte[] publicKey
		
	) {
		
		byte[]	C				= new byte[QTESLAParameter.HASH];
		byte[]	cSignature		= new byte[QTESLAParameter.HASH];
		byte[]	seed			= new byte[QTESLAParameter.SEED];
		byte[]	hashMessage		= new byte[QTESLAParameter.MESSAGE];
		int[]	newPublicKey	= new int[parameter.n];
		
		int[] 	positionList	= new int[parameter.h];
		short[] signList		= new short[parameter.h];
		
		int[] W		= new int[parameter.n];
		int[] Z		= new int[parameter.n];
		int[] TC	= new int[parameter.n];
		int[] A		= new int[parameter.n];
		
		if (signatureLength < parameter.signatureSize) {
			
			return -1;
			
		}
		
		qTESLAPack.decodeSignature (C, Z, signature, signatureOffset);
		
		/* Check Norm of Z */
		if (testZ (Z) == true) {
			
			return -2;
			
		}
		
		qTESLAPack.decodePublicKey (newPublicKey, seed, 0, publicKey);
		
		/* Generate A Polynomial */
		polynomial.polynomialUniform (A, seed, 0);
		
		encodeC (positionList, signList, C, 0);
		
		/* W = A * Z - TC */
		polynomial.sparsePolynomialMultiplication32 (TC, newPublicKey, positionList, signList);
		
		polynomial.polynomialMultiplication (W, A, Z);
		
		polynomial.polynomialSubtractionReduction (W, W, TC);
		
		if (parameter.parameterSet == "qTESLA-I") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (
				
				hashMessage, 0, QTESLAParameter.MESSAGE,
				signature, parameter.signatureSize, signatureLength - parameter.signatureSize
			
			);
			
		}
		
		if (
				parameter.parameterSet == "qTESLA-III-Speed" ||
				parameter.parameterSet == "qTESLA-III-Size"
				
		) {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
				
				hashMessage, 0, QTESLAParameter.MESSAGE,
				signature, parameter.signatureSize, signatureLength - parameter.signatureSize
			
			);
			
		}
		
		/* Obtain the Hash Symbol */
		hashFunction (cSignature, 0, W, hashMessage, 0);
		
		/* Check if Same With One from Signature */
		if (Common.memoryEqual (C, 0, cSignature, 0, QTESLAParameter.HASH) == false) {
			
			return -3;
			
		}
		
		messageLength[0] = signatureLength - parameter.signatureSize;
		
		System.arraycopy (
				
			signature, signatureOffset + parameter.signatureSize, message, messageOffset, messageLength[0]
					
		);
		
		return 0;

	}
	
	/*****************************************************************************************************
	 * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for
	 *				A Given Signature Package for Provably Secure qTESLA
	 * 
	 * @param 		signature							Given Signature Package
	 * @param		signatureOffset						Starting Point of the Given Signature Package
	 * @param		signatureLength						Length of the Given Signature Package
	 * @param		message								Original (Signed) Message
	 * @param		messageOffset						Starting Point of the Original (Signed) Message
	 * @param		messageLength						Length of the Original (Signed) Message
	 * @param		publicKey							Public Key
	 * 
	 * @return		0									Valid Signature
	 * 				< 0									Invalid Signature
	 *****************************************************************************************************/
	public int verify_MB (
			
			byte[] message, int messageOffset, int[] messageLength,
			final byte[] signature, int signatureOffset, int signatureLength,
			final byte[] publicKey
			
	) {
		
		byte[]	C					= new byte[QTESLAParameter.HASH];
		byte[]	cSignature			= new byte[QTESLAParameter.HASH];
		byte[]	seed				= new byte[QTESLAParameter.SEED];
		byte[]	hashMessage			= new byte[2 * 40];
		int[]	newPublicKey		= new int[parameter.n * parameter.k];
		
		int[]	positionList		= new int[parameter.h];
		short[]	signList			= new short[parameter.h];
		
		int[] W							= new int[parameter.n * parameter.k];
		int[] Z							= new int[parameter.n];
		int[] numberTheoreticTransformZ	= new int[parameter.n];
		int[] TC							= new int[parameter.n * parameter.k];
		int[] A							= new int[parameter.n * parameter.k];
		
		if (signatureLength < parameter.signatureSize) {			
			return -1;			
		}
		
		qTESLAPack.decodeSignature_MB (C, Z, signature, signatureOffset);
		
		/* Check Norm of Z */
		if (testZ (Z) == true) {			
			return -2;			
		}
		
		qTESLAPack.decodePublicKey_MB (newPublicKey, seed, 0, publicKey);
		
		/* Generate A Polynomial */
		polynomial.polynomialUniform_MB (A, seed, 0);
		
		encodeC (positionList, signList, C, 0);
		
		polynomial.polynomialNumberTheoreticTransform_MB (numberTheoreticTransformZ, Z);
		
		/* W_i = A_i * Z_i - TC_i for All i */
		for (int i = 0; i < parameter.k; i++) {
			
			polynomial.polynomialMultiplication_MB (					
				W, parameter.n * i, A, parameter.n * i, numberTheoreticTransformZ, 0				
			);			

			
			polynomial.sparsePolynomialMultiplication32_MB (
					
				TC, parameter.n * i, newPublicKey, parameter.n * i, positionList, signList
				
			);
			polynomial.polynomialSubtractionReduction_MB (W, parameter.n * i, W, parameter.n * i, TC, parameter.n * i);
			
		}	
		
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (				
			hashMessage, 0, 40, signature, parameter.signatureSize, signatureLength - parameter.signatureSize
		);
		
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (				
				hashMessage, 40, 40, publicKey, 0, parameter.publicKeySize -QTESLAParameter.SEED
		);		

		
		/* Obtain the Hash Symbol */
		hashFunction_MB (cSignature, W, hashMessage, 0);
		
		/* Check if Same with One from Signature */
		if (Common.memoryEqual (C, 0, cSignature, 0, QTESLAParameter.HASH) == false) {			
			return -3;			
		}
		
		messageLength[0] = signatureLength - parameter.signatureSize;
		
		System.arraycopy (				
			signature, signatureOffset + parameter.signatureSize, message, messageOffset, messageLength[0]					
		);
		
		return 0;

	}
	
	
	public int verifyP (
			
			byte[] message, int messageOffset, int[] messageLength,
			final byte[] signature, int signatureOffset, int signatureLength,
			final byte[] publicKey
			
	) {
		
		byte[]	C					= new byte[QTESLAParameter.HASH];
		byte[]	cSignature			= new byte[QTESLAParameter.HASH];
		byte[]	seed				= new byte[QTESLAParameter.SEED];
		byte[]	hashMessage			= new byte[QTESLAParameter.MESSAGE];
		int[]	newPublicKey		= new int[parameter.n * parameter.k];
		
		int[]	positionList		= new int[parameter.h];
		short[]	signList			= new short[parameter.h];
		
		long[] W							= new long[parameter.n * parameter.k];
		long[] Z							= new long[parameter.n];
		long[] numberTheoreticTransformZ	= new long[parameter.n];
		long[] TC							= new long[parameter.n * parameter.k];
		long[] A							= new long[parameter.n * parameter.k];
		
		if (signatureLength < parameter.signatureSize) {
			
			return -1;
			
		}
		
		qTESLAPack.decodeSignature (C, Z, signature, signatureOffset);
		
		/* Check Norm of Z */
		if (testZ (Z) == true) {
			
			return -2;
			
		}
		
		qTESLAPack.decodePublicKey (newPublicKey, seed, 0, publicKey);
		
		/* Generate A Polynomial */
		polynomial.polynomialUniform (A, seed, 0);
		
		encodeC (positionList, signList, C, 0);
		
		polynomial.polynomialNumberTheoreticTransform (numberTheoreticTransformZ, Z);
		
		/* W_i = A_i * Z_i - TC_i for All i */
		for (int i = 0; i < parameter.k; i++) {
			
			polynomial.polynomialMultiplication (
					
				W, parameter.n * i, A, parameter.n * i, numberTheoreticTransformZ, 0
				
			);	
			
			polynomial.sparsePolynomialMultiplication32 (
					
				TC, parameter.n * i, newPublicKey, parameter.n * i, positionList, signList
				
			);
			
			polynomial.polynomialSubtraction (W, parameter.n * i, W, parameter.n * i, TC, parameter.n * i);
		
		}
		
		if (parameter.parameterSet == "qTESLA-P-I") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK128 (
				
				hashMessage, 0, QTESLAParameter.MESSAGE,
				signature, parameter.signatureSize, signatureLength - parameter.signatureSize
			
			);
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-III") {
			
			FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
				
				hashMessage, 0, QTESLAParameter.MESSAGE,
				signature, parameter.signatureSize, signatureLength - parameter.signatureSize
			
			);
			
		}
		
		/* Obtain the Hash Symbol */
		hashFunction (cSignature, 0, W, hashMessage, 0);
		
		/* Check if Same with One from Signature */
		if (Common.memoryEqual (C, 0, cSignature, 0, QTESLAParameter.HASH) == false) {
			
			return -3;
			
		}
		
		messageLength[0] = signatureLength - parameter.signatureSize;
		
		System.arraycopy (
				
			signature, signatureOffset + parameter.signatureSize, message, messageOffset, messageLength[0]
					
		);
		
		return 0;

	}
		
}