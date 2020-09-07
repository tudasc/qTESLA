package qTESLA;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class SigningThread extends Thread {
	
	private static QTESLAParameter parameter;
	private static Polynomial polynomial;	
	private static QTESLAYSampler qTESLAYSampler;	
	private static RandomNumberGenerator randomNumberGenerator;
	
	private CountDownLatch countDownLatch;
	
	public int _threadnum, _messageLength;
	private byte[] _privateKey, _message, _randomness;
	 		int number_threads = 16;
	
	public byte[] C;
	public int[] Z;
	public long cnt; 
	
	SigningThread(int tn, CountDownLatch countDownLatch, byte[] privateKey, byte[] message, int messageLength, 
			RandomNumberGenerator randomNumberGenerator2, QTESLAYSampler qTESLAYSampler2, QTESLAParameter parameter2, Polynomial polynomial2) {
		
		_threadnum = tn;
		_privateKey = privateKey;
		_message = message;
		_messageLength = messageLength;
		_randomness = new byte[QTESLAParameter.SEED];
		randomNumberGenerator = randomNumberGenerator2;
		this.countDownLatch = countDownLatch;
		
		parameter = parameter2;
		polynomial = polynomial2;
		qTESLAYSampler = qTESLAYSampler2;
		
		C = new byte[QTESLAParameter.HASH];	
		Z = new int[parameter.n];
	}
	
	
	
	public void run () 	
	{		
		byte[] randomnessInput =
				new byte[QTESLAParameter.RANDOM + QTESLAParameter.SEED + 2 * parameter.h];
		try {
			randomNumberGenerator.randomByte (randomnessInput, QTESLAParameter.RANDOM, QTESLAParameter.RANDOM);
		} 
		catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException
				| NoSuchPaddingException | ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		int[] A = new int[parameter.n * parameter.k];	
		
		System.arraycopy (			
				_privateKey, parameter.privateKeySize - parameter.h - QTESLAParameter.SEED, 
				randomnessInput, 0, QTESLAParameter.SEED		
		);

		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (
			randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED, 
			parameter.h, _message, 0, _messageLength
		
		);		
		
		FederalInformationProcessingStandard202.secureHashAlgorithmKECCAK256 (			
			_randomness, 0, QTESLAParameter.SEED,
			randomnessInput, 0, QTESLAParameter.RANDOM + QTESLAParameter.SEED + parameter.h	
		);
		
		System.arraycopy (			
				_privateKey, parameter.privateKeySize - parameter.h, randomnessInput,
				QTESLAParameter.RANDOM + QTESLAParameter.RANDOM + parameter.h, parameter.h		
		);				

		polynomial.polynomialUniform_MB (A, _privateKey, parameter.privateKeySize - parameter.h - 2 * QTESLAParameter.SEED);
		
		int succthread = -1;
		int nonce = 0;
		boolean response = false;
		
		int[] Y							= new int[parameter.n];
		int[] V							= new int[parameter.n * parameter.k];
		int[] numberTheoreticTransformY	= new int[parameter.n];
		int[] SC							= new int[parameter.n];
		int[] positionList				= new int[parameter.h];
		short[] signList				= new short[parameter.h];
		int[] EC							= new int[parameter.n * parameter.k];	
		
		cnt=0;
		// Loop Due to Possible Rejection
		while (succthread < 0) {	
			cnt++;
			// Sample Y Uniformly Random from -B to B
			qTESLAYSampler.sampleY_MB (Y, _randomness, 0, ++nonce);
			
			for(int g=0; g<numberTheoreticTransformY.length; g++) numberTheoreticTransformY[g]=0;
			polynomial.polynomialNumberTheoreticTransform_MB (numberTheoreticTransformY, Y);
			
			// V_i = A_i * Y Modulo Q for All i
			for(int g=0; g<V.length; g++) V[g]=0;
			for (int k = 0; k < parameter.k; k++) {				
				polynomial.polynomialMultiplication_MB(V, k*parameter.n, A, k*parameter.n, numberTheoreticTransformY, 0);					
			}
			
			for(int g=0; g<C.length; g++) C[g]=0;
			hashFunction_MB (C, V, randomnessInput, QTESLAParameter.RANDOM + QTESLAParameter.SEED);
			
			// Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message
			encodeC (positionList, signList, C, 0);
			
			for(int g=0; g<SC.length; g++) SC[g]=0;
			polynomial.sparsePolynomialMultiplication8_MB (SC, 0, _privateKey, 0, positionList, signList);
			
			// Z = Y + EC modulo Q
			for(int g=0; g<Z.length; g++) Z[g]=0;
			polynomial.polynomialAddition_MB (Z, 0, Y, 0, SC, 0);
			
			// Rejection Sampling
			if (testRejection (Z) == true) {				
				continue;				
			}
			
			for (int i = 0; i < parameter.k; i++) {				
				polynomial.sparsePolynomialMultiplication8_MB (						
					EC, parameter.n * i, _privateKey, parameter.n * (i + 1), positionList, signList					
				);
				
				// V_i = V_i - EC_i Modulo Q for All k
				polynomial.polynomialSubtraction_MB (V, parameter.n * i, V, parameter.n * i, EC, parameter.n * i);
				
				response = testCorrectness_MB (V, parameter.n * i);				
				if (response == true) {				
					break;					
				}			
			}
			
			if (response == true) {				
				continue;				
			}
			
			succthread=1;
			break;
		}			
		
		QTESLA.done();
		countDownLatch.countDown();
	}
	
	
	/**********************************************************************************************************************
	 * Description:	Hash Function to Generate C' for Provably Secure qTESLA
	 **********************************************************************************************************************/
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
	private static boolean testRejection (int[] Z) {		
		for (int i = 0; i < parameter.n; i++) {
			
			if (Common.absolute (Z[i]) > (parameter.b - parameter.boundS)) {				
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
};



