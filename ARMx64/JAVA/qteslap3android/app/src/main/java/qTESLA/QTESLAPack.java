/******************************************************************************
* qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
*
* Packing Functions
* 
* @author Yinhua Xu
*******************************************************************************/

package qTESLA;

public class QTESLAPack {
	
	private static QTESLAParameter parameter;
	
	/**************************************************
	 * Pack Constructor
	 * 
	 * @param parameterSet		qTESLA Parameter Set
	 **************************************************/
	public QTESLAPack (String parameterSet) {
		
		parameter = new QTESLAParameter (parameterSet);
		
	}
	
	/*********************************************
	 * Getter of qTESLA Parameter Object
	 * 
	 * @return	none
	 *********************************************/
	public QTESLAParameter getQTESLAParameter () {
		
		return parameter;
		
	}
	
	/*****************************************************************************************************************
	 * Description:	Encode Private Key for Heuristic qTESLA
	 * 
	 * @param		privateKey				Private Key
	 * @param		secretPolynomial		Coefficients of the Secret Polynomial
	 * @param		errorPolynomial			Coefficients of the Error Polynomial
	 * @param		seed					Kappa-Bit Seed
	 * @param		seedOffset				Starting Point of the Kappa-Bit Seed
	 * 
	 * @return		none
	 *****************************************************************************************************************/
	public void encodePrivateKey_MB (
			
			byte[] privateKey, final int[] secretPolynomial, final int[] errorPolynomial,
			final byte[] seed, int seedOffset, byte[] hashPrivateKey
			
		) {		
		
			int j = 0;
			
			  for (int i=0; i < parameter.n; i++) {
				  privateKey[i] = (byte) secretPolynomial[i];
			  }
			  
			  int skoffset = parameter.n;
			  for(int k=0; k < parameter.k; k++) {
				  for(int i=0; i < parameter.n; i++) {
					  privateKey[skoffset + k* parameter.n + i] = (byte)errorPolynomial [k * parameter.n + i];
				  }			  
			  }
			
			 // memcpy(&sk[PARAM_K*PARAM_N], seeds, 2*CRYPTO_SEEDBYTES);
			System.arraycopy (					
				seed, seedOffset, privateKey, parameter.n * parameter.k + skoffset, QTESLAParameter.SEED * 2				
			);
			
			// memcpy(&sk[PARAM_K*PARAM_N + 2*CRYPTO_SEEDBYTES], hash_pk, HM_BYTES);
			System.arraycopy (					
					hashPrivateKey, 0, privateKey, parameter.n * parameter.k + QTESLAParameter.SEED * 2+ skoffset, parameter.h				
				);			
		}
	
	public void encodePrivateKey (
			
		byte[] privateKey, final int[] secretPolynomial, final int[] errorPolynomial,
		final byte[] seed, int seedOffset
		
	) {
		
		int j = 0;
		
		if (parameter.parameterSet == "qTESLA-I") {
		
			for (int i = 0; i < parameter.n; i += 4) {
			
				privateKey[j + 0] = (byte)    secretPolynomial[i + 0];
				privateKey[j + 1] = (byte) (((secretPolynomial[i + 0] >> 8) & 0x03) | (secretPolynomial[i + 1] << 2));
				privateKey[j + 2] = (byte) (((secretPolynomial[i + 1] >> 6) & 0x0F) | (secretPolynomial[i + 2] << 4));
				privateKey[j + 3] = (byte) (((secretPolynomial[i + 2] >> 4) & 0x3F) | (secretPolynomial[i + 3] << 6));
				privateKey[j + 4] = (byte)   (secretPolynomial[i + 3] >> 2);
			
				j += 5;
			
			}
		
			for (int i = 0; i < parameter.n; i += 4) {
			
				privateKey[j + 0] = (byte)    errorPolynomial[i + 0];
				privateKey[j + 1] = (byte) (((errorPolynomial[i + 0] >> 8) & 0x03) | (errorPolynomial[i + 1] << 2));
				privateKey[j + 2] = (byte) (((errorPolynomial[i + 1] >> 6) & 0x0F) | (errorPolynomial[i + 2] << 4));
				privateKey[j + 3] = (byte) (((errorPolynomial[i + 2] >> 4) & 0x3F) | (errorPolynomial[i + 3] << 6));
				privateKey[j + 4] = (byte)   (errorPolynomial[i + 3] >> 2);
			
				j += 5;
			
			}
		
		}

		if (parameter.parameterSet == "qTESLA-III-Speed") {
			
			for (int i = 0; i < parameter.n; i += 8) {
				
				privateKey[j + 0] = (byte)    secretPolynomial[i + 0];
				privateKey[j + 1] = (byte) (((secretPolynomial[i + 0] >> 8) & 0x01) | (secretPolynomial[i + 1] << 1));
				privateKey[j + 2] = (byte) (((secretPolynomial[i + 1] >> 7) & 0x03) | (secretPolynomial[i + 2] << 2));
				privateKey[j + 3] = (byte) (((secretPolynomial[i + 2] >> 6) & 0x07) | (secretPolynomial[i + 3] << 3));
				privateKey[j + 4] = (byte) (((secretPolynomial[i + 3] >> 5) & 0x0F) | (secretPolynomial[i + 4] << 4));
				privateKey[j + 5] = (byte) (((secretPolynomial[i + 4] >> 4) & 0x1F) | (secretPolynomial[i + 5] << 5));
				privateKey[j + 6] = (byte) (((secretPolynomial[i + 5] >> 3) & 0x3F) | (secretPolynomial[i + 6] << 6));
				privateKey[j + 7] = (byte) (((secretPolynomial[i + 6] >> 2) & 0x7F) | (secretPolynomial[i + 7] << 7));
				privateKey[j + 8] = (byte)   (secretPolynomial[i + 7] >> 1);
				
				j += 9;
				
			}
			
			for (int i = 0; i < parameter.n; i += 8) {
				
				privateKey[j + 0] = (byte)    errorPolynomial[i + 0];
				privateKey[j + 1] = (byte) (((errorPolynomial[i + 0] >> 8) & 0x01) | (errorPolynomial[i + 1] << 1));
				privateKey[j + 2] = (byte) (((errorPolynomial[i + 1] >> 7) & 0x03) | (errorPolynomial[i + 2] << 2));
				privateKey[j + 3] = (byte) (((errorPolynomial[i + 2] >> 6) & 0x07) | (errorPolynomial[i + 3] << 3));
				privateKey[j + 4] = (byte) (((errorPolynomial[i + 3] >> 5) & 0x0F) | (errorPolynomial[i + 4] << 4));
				privateKey[j + 5] = (byte) (((errorPolynomial[i + 4] >> 4) & 0x1F) | (errorPolynomial[i + 5] << 5));
				privateKey[j + 6] = (byte) (((errorPolynomial[i + 5] >> 3) & 0x3F) | (errorPolynomial[i + 6] << 6));
				privateKey[j + 7] = (byte) (((errorPolynomial[i + 6] >> 2) & 0x7F) | (errorPolynomial[i + 7] << 7));
				privateKey[j + 8] = (byte)   (errorPolynomial[i + 7] >> 1);
				
				j += 9;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-III-Size") {
			
			for (int i = 0; i < parameter.n; i++) {
				
				privateKey[i] = (byte) secretPolynomial[i];
				
			}
			
			for (int i = 0; i < parameter.n; i++) {
				
				privateKey[parameter.n + i] = (byte) errorPolynomial[i];
				
			}
			
		}
		
		/*System.arraycopy (
				
				seedA, seedAOffset, publicKey, parameter.n * parameter.k * parameter.qLogarithm / Byte.SIZE, QTESLAParameter.SEED
				
			);*/
		
	}
	
	/***********************************************************************************************************************
	 * Description:	Decode Private Key for Heuristic qTESLA
	 * 
	 * @param		seed					Kappa-Bit Seed
	 * @param		secretPolynomial		Coefficients of the Secret Polynomial
	 * @param		errorPolynomial			Coefficients of the Error Polynomial
	 * @param		privateKey				Private Key
	 * 
	 * @return		none
	 ***********************************************************************************************************************/
	public void decodePrivateKey (byte[] seed, short[] secretPolynomial, short[] errorPolynomial, final byte[] privateKey) {
		
		int j = 0;
		int temporary = 0;
		
		if (parameter.parameterSet == "qTESLA-I") {
		
			for (int i = 0; i < parameter.n; i += 4) {
			
				temporary = privateKey[j + 0] & 0xFF;
				secretPolynomial[i + 0]  = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 30) >> 22;
				secretPolynomial[i + 0] |= (short) temporary;
			
				temporary = privateKey[j + 1] & 0xFF;
				temporary =  temporary >> 2;
				secretPolynomial[i + 1]  = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 28) >> 22;
				secretPolynomial[i + 1] |= (short) temporary;
			
				temporary = privateKey[j + 2] & 0xFF;
				temporary =  temporary >> 4;
				secretPolynomial[i + 2]  = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 26) >> 22;
				secretPolynomial[i + 2] |= (short) temporary;
			
				temporary = privateKey[j + 3] & 0xFF;
				temporary =  temporary >> 6;
				secretPolynomial[i + 3]  = (short) temporary;
				temporary = privateKey[j + 4];
				temporary = (short) temporary << 2;
				secretPolynomial[i + 3] |= (short) temporary;
			
				j += 5;
			
			}
		
			for (int i = 0; i < parameter.n; i += 4) {
			
				temporary = privateKey[j + 0] & 0xFF;
				errorPolynomial[i + 0]  = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 30) >> 22;
				errorPolynomial[i + 0] |= (short) temporary;
			
				temporary = privateKey[j + 1] & 0xFF;
				temporary =  temporary >> 2;
				errorPolynomial[i + 1]  = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 28) >> 22;
				errorPolynomial[i + 1] |= (short) temporary;
			
				temporary = privateKey[j + 2] & 0xFF;
				temporary =  temporary >> 4;
				errorPolynomial[i + 2]  = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 26) >> 22;
				errorPolynomial[i + 2] |= (short) temporary;
			
				temporary = privateKey[j + 3] & 0xFF;
				temporary =  temporary >> 6;
				errorPolynomial[i + 3]  = (short) temporary;
				temporary = privateKey[j + 4];
				temporary = (short) temporary << 2;
				errorPolynomial[i + 3] |= (short) temporary;
			
				j += 5;
			
			}
		
		}
		
		if (parameter.parameterSet == "qTESLA-III-Speed") {
			
			for (int i = 0; i < parameter.n; i += 8) {
				
				temporary = privateKey[j + 0] & 0xFF;
				secretPolynomial[i + 0]  = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				secretPolynomial[i + 0] |= (short) temporary;
				
				temporary = privateKey[j + 1] & 0xFF;
				temporary =  temporary >> 1;
				secretPolynomial[i + 1]  = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				secretPolynomial[i + 1] |= (short) temporary;
				
				temporary = privateKey[j + 2] & 0xFF;
				temporary =  temporary >> 2;
				secretPolynomial[i + 2]  = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				secretPolynomial[i + 2] |= (short) temporary;
				
				temporary = privateKey[j + 3] & 0xFF;
				temporary =  temporary >> 3;
				secretPolynomial[i + 3]  = (short) temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				secretPolynomial[i + 3] |= (short) temporary;
				
				temporary = privateKey[j + 4] & 0xFF;
				temporary =  temporary >> 4;
				secretPolynomial[i + 4]  = (short) temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				secretPolynomial[i + 4] |= (short) temporary;
				
				temporary = privateKey[j + 5] & 0xFF;
				temporary =  temporary >> 5;
				secretPolynomial[i + 5]  = (short) temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				secretPolynomial[i + 5] |= (short) temporary;
				
				temporary = privateKey[j + 6] & 0xFF;
				temporary =  temporary >> 6;
				secretPolynomial[i + 6]  = (short) temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				secretPolynomial[i + 6] |= (short) temporary;
				
				temporary = privateKey[j + 7] & 0xFF;
				temporary =  temporary >> 7;
				secretPolynomial[i + 7]  = (short) temporary;
				temporary = privateKey[j + 8];
				temporary = (short) temporary << 1;
				secretPolynomial[i + 7] |= (short) temporary;
				
				j += 9;
				
			}
			
			for (int i = 0; i < parameter.n; i += 8) {
				
				temporary = privateKey[j + 0] & 0xFF;
				errorPolynomial[i + 0]  = (short) temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				errorPolynomial[i + 0] |= (short) temporary;
				
				temporary = privateKey[j + 1] & 0xFF;
				temporary =  temporary >> 1;
				errorPolynomial[i + 1]  = (short) temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				errorPolynomial[i + 1] |= (short) temporary;
				
				temporary = privateKey[j + 2] & 0xFF;
				temporary =  temporary >> 2;
				errorPolynomial[i + 2]  = (short) temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				errorPolynomial[i + 2] |= (short) temporary;
				
				temporary = privateKey[j + 3] & 0xFF;
				temporary =  temporary >> 3;
				errorPolynomial[i + 3]  = (short) temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				errorPolynomial[i + 3] |= (short) temporary;
				
				temporary = privateKey[j + 4] & 0xFF;
				temporary =  temporary >> 4;
				errorPolynomial[i + 4]  = (short) temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				errorPolynomial[i + 4] |= (short) temporary;
				
				temporary = privateKey[j + 5] & 0xFF;
				temporary =  temporary >> 5;
				errorPolynomial[i + 5]  = (short) temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				errorPolynomial[i + 5] |= (short) temporary;
				
				temporary = privateKey[j + 6] & 0xFF;
				temporary =  temporary >> 6;
				errorPolynomial[i + 6]  = (short) temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				errorPolynomial[i + 6] |= (short) temporary;
				
				temporary = privateKey[j + 7] & 0xFF;
				temporary =  temporary >> 7;
				errorPolynomial[i + 7]  = (short) temporary;
				temporary = privateKey[j + 8];
				temporary = (short) temporary << 1;
				errorPolynomial[i + 7] |= (short) temporary;
				
				j += 9;
				
			}
		
		}
		
		if (parameter.parameterSet == "qTESLA-III-Size") {
			
			for (int i = 0; i < parameter.n; i++) {
				
				secretPolynomial[i] = privateKey[i];
				
			}
			
			for (int i = 0; i < parameter.n; i++) {
				
				errorPolynomial[i] = privateKey[parameter.n + i];
				
			}
			
		}
		
		System.arraycopy (
				
			privateKey, parameter.n * parameter.sBit * 2 / Byte.SIZE, seed, 0, QTESLAParameter.SEED * 2
		
		);
		
	}
	
	/********************************************************************************************************
	 * Description:	Pack Private Key for Provably Secure qTESLA Security
	 * 
	 * @param		privateKey				Private Key
	 * @param		secretPolynomial		Coefficients of the Secret Polynomial
	 * @param		errorPolynomial			Coefficients of the Error Polynomial
	 * @param		seed					Kappa-Bit Seed
	 * @param		seedOffset				Starting Point of the Kappa-Bit Seed
	 * 
	 * @return		none
	 ********************************************************************************************************/
	public void packPrivateKey (
			
		byte[] privateKey, final long[] secretPolynomial, final long[] errorPolynomial,
		final byte[] seed, int seedOffset
	
	) {
		
		for (int i = 0; i < parameter.n; i++) {
			
			privateKey[i] = (byte) secretPolynomial[i];
			
		}
		
		for (int j = 0; j < parameter.k; j++) {
			
			for (int i = 0; i < parameter.n; i++) {
				
				privateKey[parameter.n + j * parameter.n + i]	= (byte) errorPolynomial[j * parameter.n + i];
				
			}
			
		}
		
		System.arraycopy (
				
			seed, seedOffset, privateKey, parameter.n + parameter.k * parameter.n, QTESLAParameter.SEED * 2
			
		);
		
	}
	
	/*********************************************************************************************************************************************
	 * Description:	Encode Public Key for Heuristic qTESLA
	 * 
	 * @param		publicKey			Public Key
	 * @param		T					T_1, ..., T_k
	 * @param		seedA				Seed Used to Generate the Polynomials a_i for i = 1, ..., k
	 * @param		seedAOffset			Starting Point of the Seed A
	 * 
	 * @return		none
	 *********************************************************************************************************************************************/
	public void encodePublicKey (byte[] publicKey, final int[] T, final byte[] seedA, int seedAOffset) {
		
		int j = 0;
		
		if (parameter.parameterSet == "qTESLA-I" || parameter.parameterSet == "qTESLA-III-Size") {
			
			for (int i = 0; i < parameter.n * parameter.qLogarithm / Integer.SIZE; i += parameter.qLogarithm) {
				
				Common.store32 (
					
					publicKey, Integer.SIZE / Byte.SIZE * (i +  0),
					(int) ( T[j +  0]        | (T[j +  1] << 23))
				
				);
				
				Common.store32 (
					
					publicKey, Integer.SIZE / Byte.SIZE * (i +  1),
					(int) ((T[j +  1] >>  9) | (T[j +  2] << 14))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  2),
					(int) ((T[j +  2] >> 18) | (T[j +  3] <<  5) | (T[j +  4] << 28))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  3),
					(int) ((T[j +  4] >>  4) | (T[j +  5] << 19))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  4),
					(int) ((T[j +  5] >> 13) | (T[j +  6] << 10))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  5),
					(int) ((T[j +  6] >> 22) | (T[j +  7] <<  1) | (T[j +  8] << 24))
				
				);
				
				Common.store32 (
					
					publicKey, Integer.SIZE / Byte.SIZE * (i +  6),
					(int) ((T[j +  8] >>  8) | (T[j +  9] << 15))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  7),
					(int) ((T[j +  9] >> 17) | (T[j + 10] <<  6) | (T[j + 11] << 29))
				
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  8),
					(int) ((T[j + 11] >>  3) | (T[j + 12] << 20))
					
				);
				
				Common.store32 (
					
					publicKey, Integer.SIZE / Byte.SIZE * (i +  9),
					(int) ((T[j + 12] >> 12) | (T[j + 13] << 11))
					
				);
				
				Common.store32 (
					
					publicKey, Integer.SIZE / Byte.SIZE * (i + 10),
					(int) ((T[j + 13] >> 21) | (T[j + 14] <<  2) | (T[j + 15] << 25))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 11),
					(int) ((T[j + 15] >>  7) | (T[j + 16] << 16))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 12),
					(int) ((T[j + 16] >> 16) | (T[j + 17] <<  7) | (T[j + 18] << 30))
				
				);
				
				Common.store32 (
					
					publicKey, Integer.SIZE / Byte.SIZE * (i + 13),
					(int) ((T[j + 18] >>  2) | (T[j + 19] << 21))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 14),
					(int) ((T[j + 19] >> 11) | (T[j + 20] << 12))
				
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 15),
					(int) ((T[j + 20] >> 20) | (T[j + 21] <<  3) | (T[j + 22] << 26))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 16),
					(int) ((T[j + 22] >>  6) | (T[j + 23] << 17))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 17),
					(int) ((T[j + 23] >> 15) | (T[j + 24] <<  8) | (T[j + 25] << 31))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 18),
					(int) ((T[j + 25] >>  1) | (T[j + 26] << 22))
				
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 19),
					(int) ((T[j + 26] >> 10) | (T[j + 27] << 13))
				
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 20),
					(int) ((T[j + 27] >> 19) | (T[j + 28] <<  4) | (T[j + 29] << 27))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 21),
					(int) ((T[j + 29] >>  5) | (T[j + 30] << 18))
					
				);
				
				Common.store32 (
					
					publicKey, Integer.SIZE / Byte.SIZE * (i + 22),
					(int) ((T[j + 30] >> 14) | (T[j + 31] <<  9))
					
				);
				
				j += Integer.SIZE;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-III-Speed") {
			
			for (int i = 0; i < parameter.n * parameter.qLogarithm / Integer.SIZE; i += (parameter.qLogarithm / Byte.SIZE)) {
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 0),
					(int) ( T[j + 0]        | (T[j + 1] << 24))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 1),
					(int) ((T[j + 1] >>  8) | (T[j + 2] << 16))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 2),
					(int) ((T[j + 2] >> 16) | (T[j + 3] <<  8))
					
				);
				
				j += Integer.SIZE / Byte.SIZE;
				
			}
			
		}
		
		System.arraycopy (
				
			seedA, seedAOffset, publicKey, parameter.n * parameter.qLogarithm / Byte.SIZE, QTESLAParameter.SEED
			
		);
		
	}
		
	/*************************************************************************************************************************
	 * Description:	Encode Public Key for Provably Secure qTESLA
	 * 
	 * @param		publicKey			Public Key
	 * @param		T					T_1, ..., T_k
	 * @param		seedA				Seed Used to Generate the Polynomials a_i for i = 1, ..., k
	 * @param		seedAOffset			Starting Point of the Seed A
	 * 
	 * @return		none
	 *************************************************************************************************************************/
	public void encodePublicKey_MB (byte[] publicKey, final int[] T, final byte[] seedA, int seedAOffset) {		
		int j = 0;
		int temp;
		for (int i = 0; i < parameter.n * parameter.k * parameter.qLogarithm / Integer.SIZE; i += 15) {
		    temp = ( T[j+ 0]        | (T[j+ 1] << 30));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 0), temp);
		    
		    temp = ((T[j+ 1] >>  2) | (T[j+ 2] << 28));	
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 1), temp);
		    
		    temp = ((T[j+ 2] >>  4) | (T[j+ 3] << 26));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 2), temp);
		    
		    temp = ((T[j+ 3] >>  6) | (T[j+ 4] << 24));			
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 3), temp);
		    
		    temp = ((T[j+ 4] >>  8) | (T[j+ 5] << 22));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 4), temp);
		    
		    temp = ((T[j+ 5] >> 10) | (T[j+ 6] << 20));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 5), temp);
		    
		    temp = ((T[j+ 6] >> 12) | (T[j+ 7] << 18));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 6), temp);
		    
		    temp = ((T[j+ 7] >> 14) | (T[j+ 8] << 16));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 7), temp);
		    
		    temp = ((T[j+ 8] >> 16) | (T[j+ 9] << 14));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 8), temp);
		    
		    temp = ((T[j+ 9] >> 18) | (T[j+10] << 12));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 9), temp);
		    
		    temp = ((T[j+10] >> 20) | (T[j+11] << 10));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 10), temp);
		    
		    temp = ((T[j+11] >> 22) | (T[j+12] <<  8));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 11), temp);
		    
		    temp = ((T[j+12] >> 24) | (T[j+13] <<  6));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 12), temp);
		    
		    temp = ((T[j+13] >> 26) | (T[j+14] <<  4));
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 13), temp);
		    
		    temp = ((T[j+14] >> 28) | (T[j+15] <<  2));		    
		    Common.store32 (	 publicKey, Integer.SIZE / Byte.SIZE * (i + 14), temp);				
				
				//Common.store32 (						
				//	publicKey, Integer.SIZE / Byte.SIZE * (i + index),
				//	(int) ((T[j + index] >>> index) | (T[j + index + 1] << (parameter.qLogarithm - index)))					
				//);				
			
			j += 16;				
		}
			

		
		System.arraycopy (			
			seedA, seedAOffset, publicKey, parameter.n * parameter.k * parameter.qLogarithm / Byte.SIZE, QTESLAParameter.SEED
			
		);
		
	}
	
	public void encodePublicKey (byte[] publicKey, final long[] T, final byte[] seedA, int seedAOffset) {
		
		int j = 0;
		
		if (parameter.parameterSet == "qTESLA-P-I") {
			
			for (int i = 0; i < parameter.n * parameter.k * parameter.qLogarithm / Integer.SIZE; i += parameter.qLogarithm) {
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  0),
					(int) ( T[j +  0]        | (T[j +  1] << 29))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  1),
					(int) ((T[j +  1] >>  3) | (T[j +  2] << 26))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  2),
					(int) ((T[j +  2] >>  6) | (T[j +  3] << 23))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  3),
					(int) ((T[j +  3] >>  9) | (T[j +  4] << 20))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  4),
					(int) ((T[j +  4] >> 12) | (T[j +  5] << 17))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  5),
					(int) ((T[j +  5] >> 15) | (T[j +  6] << 14))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  6),
					(int) ((T[j +  6] >> 18) | (T[j +  7] << 11))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  7),
					(int) ((T[j +  7] >> 21) | (T[j +  8] <<  8))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  8),
					(int) ((T[j +  8] >> 24) | (T[j +  9] <<  5))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i +  9),
					(int) ((T[j +  9] >> 27) | (T[j + 10] <<  2) | (T[j + 11] << 31))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 10),
					(int) ((T[j + 11] >>  1) | (T[j + 12] << 28))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 11),
					(int) ((T[j + 12] >>  4) | (T[j + 13] << 25))
					
				);
				
				Common.store32 (
					
					publicKey, Integer.SIZE / Byte.SIZE * (i + 12),
					(int) ((T[j + 13] >>  7) | (T[j + 14] << 22))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 13),
					(int) ((T[j + 14] >> 10) | (T[j + 15] << 19))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 14),
					(int) ((T[j + 15] >> 13) | (T[j + 16] << 16))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 15),
					(int) ((T[j + 16] >> 16) | (T[j + 17] << 13))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 16),
					(int) ((T[j + 17] >> 19) | (T[j + 18] << 10))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 17),
					(int) ((T[j + 18] >> 22) | (T[j + 19] <<  7))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 18),
					(int) ((T[j + 19] >> 25) | (T[j + 20] <<  4))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 19),
					(int) ((T[j + 20] >> 28) | (T[j + 21] <<  1) | (T[j + 22] << 30))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 20),
					(int) ((T[j + 22] >>  2) | (T[j + 23] << 27))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 21),
					(int) ((T[j + 23] >>  5) | (T[j + 24] << 24))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 22),
					(int) ((T[j + 24] >>  8) | (T[j + 25] << 21))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 23),
					(int) ((T[j + 25] >> 11) | (T[j + 26] << 18))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 24),
					(int) ((T[j + 26] >> 14) | (T[j + 27] << 15))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 25),
					(int) ((T[j + 27] >> 17) | (T[j + 28] << 12))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 26),
					(int) ((T[j + 28] >> 20) | (T[j + 29] <<  9))
					
				);
				
				Common.store32 (
					
					publicKey, Integer.SIZE / Byte.SIZE * (i + 27),
					(int) ((T[j + 29] >> 23) | (T[j + 30] <<  6))
					
				);
				
				Common.store32 (
						
					publicKey, Integer.SIZE / Byte.SIZE * (i + 28),
					(int) ((T[j + 30] >> 26) | (T[j + 31] <<  3))
				
				);
				
				j += Integer.SIZE;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-III") {
			
			for (int i = 0; i < parameter.n * parameter.k * parameter.qLogarithm / Integer.SIZE; i += parameter.qLogarithm) {
				
				for (int index = 0; index < parameter.qLogarithm; index++) {
					
					Common.store32 (
							
						publicKey, Integer.SIZE / Byte.SIZE * (i + index),
						(int) ((T[j + index] >> index) | (T[j + index + 1] << (parameter.qLogarithm - index)))
						
					);
					
				}
				
				j += Integer.SIZE;
				
			}
			
		}
		
		System.arraycopy (
			
			seedA, seedAOffset, publicKey, parameter.n * parameter.k * parameter.qLogarithm / Byte.SIZE, QTESLAParameter.SEED
			
		);
		
	}
	
	/**************************************************************************************************************************************
	 * Description:	Decode Public Key
	 * 
	 * @param		publicKey			Decoded Public Key
	 * @param		seedA				Seed Used to Generate the Polynomials A_i for i = 1, ..., k
	 * @param		seedAOffset			Starting Point of the Seed A
	 * @param		publicKeyInput		Public Key to be Decoded
	 *
	 * @return		none
	 **************************************************************************************************************************************/
	public void decodePublicKey_MB (int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput) {
		int j = 0;
		int maskq = ((1<<parameter.qLogarithm)-1);
	
		for (int i=0; i < parameter.n * parameter.k; i+=16) {		
		    publicKey[i+ 0] = ( Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 0))       ) & maskq;
		    publicKey[i+ 1] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 0)) >>> 30) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 1)) <<  2)) & maskq;
		    publicKey[i+ 2] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 1)) >>> 28) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 2)) <<  4)) & maskq;
		    publicKey[i+ 3] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 2)) >>> 26) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 3)) <<  6)) & maskq;
		    publicKey[i+ 4] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 3)) >>> 24) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 4)) <<  8)) & maskq;
		    publicKey[i+ 5] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 4)) >>> 22) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 5)) << 10)) & maskq;
		    publicKey[i+ 6] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 5)) >>> 20) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 6)) << 12)) & maskq;
		    publicKey[i+ 7] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 6)) >>> 18) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 7)) << 14)) & maskq;
		    publicKey[i+ 8] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 7)) >>> 16) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 8)) << 16)) & maskq;
		    publicKey[i+ 9] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 8)) >>> 14) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 9)) << 18)) & maskq;
		    publicKey[i+10] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+ 9)) >>> 12) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+10)) << 20)) & maskq;
		    publicKey[i+11] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+10)) >>> 10) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+11)) << 22)) & maskq;
		    publicKey[i+12] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+11)) >>>  8) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+12)) << 24)) & maskq;
		    publicKey[i+13] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+12)) >>>  6) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+13)) << 26)) & maskq;
		    publicKey[i+14] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+13)) >>>  4) | 
			(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+14)) << 28)) & maskq;
		    publicKey[i+15] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j+14)) >>>  2)) & maskq;
		    j += 15;
		}
		
		System.arraycopy (				
				publicKeyInput, parameter.n * parameter.k * parameter.qLogarithm / Byte.SIZE, seedA, seedAOffset, QTESLAParameter.SEED				
			);
	}
	
	
	
	public void decodePublicKey (int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput) {
		
		int j = 0;
		
		int mask = (1 << parameter.qLogarithm) - 1;
		
		if (parameter.parameterSet == "qTESLA-I" || parameter.parameterSet == "qTESLA-III-Size") {
			
			for (int i = 0; i < parameter.n; i += Integer.SIZE) {
				
				publicKey[i +  0] =   Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  0))          & mask;
				
				publicKey[i +  1] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  0)) >>> 23)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  1)) <<   9)) & mask;
				
				publicKey[i +  2] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  1)) >>> 14)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  2)) <<  18)) & mask;
				
				publicKey[i +  3] =  (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  2)) >>>  5)  & mask;
				
				publicKey[i +  4] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  2)) >>> 28)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  3)) <<   4)) & mask;
				
				publicKey[i +  5] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  3)) >>> 19)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  4)) <<  13)) & mask;
				
				publicKey[i +  6] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  4)) >>> 10)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  5)) <<  22)) & mask;
				
				publicKey[i +  7] =  (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  5)) >>>  1)  & mask;
				
				publicKey[i +  8] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  5)) >>> 24)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  6)) <<   8)) & mask;
				
				publicKey[i +  9] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  6)) >>> 15)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  7)) <<  17)) & mask;
				
				publicKey[i + 10] =  (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  7)) >>>  6)  & mask;
				
				publicKey[i + 11] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  7)) >>> 29)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  8)) <<   3)) & mask;
				
				publicKey[i + 12] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  8)) >>> 20)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  9)) <<  12)) & mask;
				
				publicKey[i + 13] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  9)) >>> 11)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) <<  21)) & mask;
				
				publicKey[i + 14] =  (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) >>>  2)  & mask;
				
				publicKey[i + 15] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) >>> 25)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 11)) <<   7)) & mask;
				
				publicKey[i + 16] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 11)) >>> 16)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) <<  16)) & mask;
				
				publicKey[i + 17] =  (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) >>>  7)  & mask;
				
				publicKey[i + 18] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) >>> 30)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 13)) <<   2)) & mask;
				
				publicKey[i + 19] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 13)) >>> 21)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 14)) <<  11)) & mask;
				
				publicKey[i + 20] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 14)) >>> 12)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) <<  20)) & mask;
				
				publicKey[i + 21] =  (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) >>>  3)  & mask;
				
				publicKey[i + 22] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) >>> 26)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 16)) <<   6)) & mask;
				
				publicKey[i + 23] =	((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 16)) >>> 17)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) <<  15)) & mask;
				
				publicKey[i + 24] =	 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) >>>  8)  & mask;
				
				publicKey[i + 25] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) >>> 31)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 18)) <<   1)) & mask;
				
				publicKey[i + 26] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 18)) >>> 22)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) <<  10)) & mask;
				
				publicKey[i + 27] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) >>> 13)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) <<  19)) & mask;
				
				publicKey[i + 28] =  (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) >>>  4)  & mask;
				
				publicKey[i + 29] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) >>> 27)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 21)) <<   5)) & mask;
				
				publicKey[i + 30] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 21)) >>> 18)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 22)) <<  14)) & mask;
				
				publicKey[i + 31] =   Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 22)) >>>  9;
			
				j += parameter.qLogarithm;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-III-Speed") {
			
			for (int i = 0; i < parameter.n; i += Integer.SIZE / Byte.SIZE) {
				
				publicKey[i + 0] =   Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 0))          & mask;
				
				publicKey[i + 1] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 0)) >>> 24)  |
									(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 1)) <<   8)) & mask;
				
				publicKey[i + 2] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 1)) >>> 16)  |
									(Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 2)) <<  16)) & mask;
				
				publicKey[i + 3] =   Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 2)) >>>  8;
			
				j += parameter.qLogarithm / Byte.SIZE;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-I") {
			
			for (int i = 0; i < parameter.n * parameter.k; i += Integer.SIZE) {
				
				publicKey[i +  0] =   Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  0))          & mask;
				
				publicKey[i +  1] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  0)) >>> 29)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  1)) <<   3)) & mask;
				
				publicKey[i +  2] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  1)) >>> 26)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  2)) <<   6)) & mask;
				
				publicKey[i +  3] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  2)) >>> 23)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  3)) <<   9)) & mask;
				
				publicKey[i +  4] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  3)) >>> 20)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  4)) <<  12)) & mask;
				
				publicKey[i +  5] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  4)) >>> 17)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  5)) <<  15)) & mask;
				
				publicKey[i +  6] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  5)) >>> 14)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  6)) <<  18)) & mask;
				
				publicKey[i +  7] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  6)) >>> 11)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  7)) <<  21)) & mask;
				
				publicKey[i +  8] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  7)) >>>  8)  |
						 			 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  8)) <<  24)) & mask;
				
				publicKey[i +  9] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  8)) >>>  5)  |
			 			 			 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  9)) <<  27)) & mask;
				
				publicKey[i + 10] =  (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  9)) >>>  2)  & mask;
				
				publicKey[i + 11] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j +  9)) >>> 31)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) <<   1)) & mask;
				
				publicKey[i + 12] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 10)) >>> 28)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 11)) <<   4)) & mask;
				
				publicKey[i + 13] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 11)) >>> 25)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) <<   7)) & mask;
				
				publicKey[i + 14] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 12)) >>> 22)  |
						 			 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 13)) <<  10)) & mask;
				
				publicKey[i + 15] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 13)) >>> 19)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 14)) <<  13)) & mask;
				
				publicKey[i + 16] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 14)) >>> 16)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) <<  16)) & mask;
				
				publicKey[i + 17] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 15)) >>> 13)  |
						 			 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 16)) <<  19)) & mask;
				
				publicKey[i + 18] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 16)) >>> 10)  |
			 			 			 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) <<  22)) & mask;
				
				publicKey[i + 19] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 17)) >>>  7)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 18)) <<  25)) & mask;
				
				publicKey[i + 20] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 18)) >>>  4)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) <<  28)) & mask;
				
				publicKey[i + 21] =  (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) >>>  1)  & mask;
				
				publicKey[i + 22] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 19)) >>> 30)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) <<   2)) & mask;
				
				publicKey[i + 23] =	((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 20)) >>> 27)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 21)) <<   5)) & mask;
				
				publicKey[i + 24] =	((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 21)) >>> 24)  |
						 			 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 22)) <<   8)) & mask;
				
				publicKey[i + 25] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 22)) >>> 21)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 23)) <<  11)) & mask;
				
				publicKey[i + 26] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 23)) >>> 18)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 24)) <<  14)) & mask;
				
				publicKey[i + 27] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 24)) >>> 15)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 25)) <<  17)) & mask;
				
				publicKey[i + 28] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 25)) >>> 12)  |
						 			 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 26)) <<  20)) & mask;
				
				publicKey[i + 29] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 26)) >>>  9)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 27)) <<  23)) & mask;
				
				publicKey[i + 30] = ((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 27)) >>>  6)  |
									 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 28)) <<  26)) & mask;
				
				publicKey[i + 31] =   Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + 28)) >>>  3;
			
				j += parameter.qLogarithm;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-III") {
			
			for (int i = 0; i < parameter.n * parameter.k; i += Integer.SIZE) {
				
				publicKey[i] = Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * j) & mask;
				
				for (int index = 1; index < parameter.qLogarithm; index++) {
					
					publicKey[i + index] =
							
						((Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + index - 1))	>>> (Integer.SIZE - index))  |
						 (Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + index    ))	<<  index				 ))  & mask;
					
				}
				
				publicKey[i + parameter.qLogarithm] =
						
						Common.load32 (publicKeyInput, Integer.SIZE / Byte.SIZE * (j + parameter.qLogarithm - 1)) >>> 1;
							 			 	
				j += parameter.qLogarithm;
			
			}
			
		}
		
		System.arraycopy (
				
			publicKeyInput, parameter.n * parameter.k * parameter.qLogarithm / Byte.SIZE, seedA, seedAOffset, QTESLAParameter.SEED
			
		);
		
	}
	
	/***************************************************************************************************************************
	 * Description:	Encode Signature for Heuristic qTESLA
	 * 
	 * @param		signature			Output Package Containing Signature
	 * @param		signatureOffset		Starting Point of the Output Package Containing Signature
	 * @param		C
	 * @param		cOffset
	 * @param		Z
	 * 
	 * @return		none
	 ***************************************************************************************************************************/
	public void encodeSignature (byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z) {
		
		int j = 0;
		
		if (parameter.parameterSet == "qTESLA-I" || parameter.parameterSet == "qTESLA-III-Size") {
			
			for (int i = 0; i < (parameter.n * parameter.d / Integer.SIZE); i += parameter.d) {
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  0),
					(int)  (((Z[j +  0]         & ((1 << 21) - 1))) |  (Z[j +  1] << 21))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  1),
					(int)  (((Z[j +  1] >>> 11) & ((1 << 10) - 1))  | ((Z[j +  2] & ((1 << 21) - 1)) << 10) | (Z[j +  3] << 31))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  2),
					(int) ((((Z[j +  3] >>>  1) & ((1 << 20) - 1))) |  (Z[j +  4] << 20))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  3),
					(int)  (((Z[j +  4] >>> 12) & ((1 <<  9) - 1))  | ((Z[j +  5] & ((1 << 21) - 1)) <<  9) | (Z[j +  6] << 30))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  4), 
					(int) ((((Z[j +  6] >>>  2) & ((1 << 19) - 1))) |  (Z[j +  7] << 19))
					
				);
				
				Common.store32 (
					
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  5),
					(int)  (((Z[j +  7] >>> 13) & ((1 <<  8) - 1))  | ((Z[j +  8] & ((1 << 21) - 1)) <<  8) | (Z[j +  9] << 29))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  6),
					(int) ((((Z[j +  9] >>>  3) & ((1 << 18) - 1))) |  (Z[j + 10] << 18))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  7),
					(int)  (((Z[j + 10] >>> 14) & ((1 <<  7) - 1))  | ((Z[j + 11] & ((1 << 21) - 1)) <<  7) | (Z[j + 12] << 28))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  8),
					(int) ((((Z[j + 12] >>>  4) & ((1 << 17) - 1))) |  (Z[j + 13] << 17))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  9),
					(int)  (((Z[j + 13] >>> 15) & ((1 <<  6) - 1))  | ((Z[j + 14] & ((1 << 21) - 1)) <<  6) | (Z[j + 15] << 27))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 10),
					(int) ((((Z[j + 15] >>>  5) & ((1 << 16) - 1))) |  (Z[j + 16] << 16))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 11),
					(int)  (((Z[j + 16] >>> 16) & ((1 <<  5) - 1))  | ((Z[j + 17] & ((1 << 21) - 1)) <<  5) | (Z[j + 18] << 26))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 12),
					(int) ((((Z[j + 18] >>>  6) & ((1 << 15) - 1))) |  (Z[j + 19] << 15))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 13),
					(int)  (((Z[j + 19] >>> 17) & ((1 <<  4) - 1))  | ((Z[j + 20] & ((1 << 21) - 1)) <<  4) | (Z[j + 21] << 25))
					
				);
				
				Common.store32 (
					
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 14),
					(int) ((((Z[j + 21] >>>  7) & ((1 << 14) - 1))) |  (Z[j + 22] << 14))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 15),
					(int)  (((Z[j + 22] >>> 18) & ((1 <<  3) - 1))  | ((Z[j + 23] & ((1 << 21) - 1)) <<  3) | (Z[j + 24] << 24))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 16),
					(int) ((((Z[j + 24] >>>  8) & ((1 << 13) - 1))) |  (Z[j + 25] << 13))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 17),
					(int)  (((Z[j + 25] >>> 19) & ((1 <<  2) - 1))  | ((Z[j + 26] & ((1 << 21) - 1)) <<  2) | (Z[j + 27] << 23))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 18),
					(int) ((((Z[j + 27] >>>  9) & ((1 << 12) - 1))) |  (Z[j + 28] << 12))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 19),
					(int)  (((Z[j + 28] >>> 20) & ((1 <<  1) - 1))  | ((Z[j + 29] & ((1 << 21) - 1)) <<  1) | (Z[j + 30] << 22))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 20),
					(int) ((((Z[j + 30] >>> 10) & ((1 << 11) - 1))) |  (Z[j + 31] << 11))
					
				);
				
				j += Integer.SIZE;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-III-Speed") {
			
			for (int i = 0; i < (parameter.n * parameter.d / Integer.SIZE); i += parameter.d / 2) {
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  0),
					(int)  (((Z[j +  0]         & ((1 << 22) - 1))) |  (Z[j +  1] << 22))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  1),
					(int) ((((Z[j +  1] >>> 10) & ((1 << 12) - 1))) |  (Z[j +  2] << 12))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  2),
					(int)  (((Z[j +  2] >>> 20) & ((1 <<  2) - 1))  | ((Z[j +  3] & ((1 << 22) - 1)) << 2) | (Z[j +  4] << 24))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  3),
					(int) ((((Z[j +  4] >>>  8) & ((1 << 14) - 1))) |  (Z[j +  5] << 14))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  4),
					(int)  (((Z[j +  5] >>> 18) & ((1 <<  4) - 1))  | ((Z[j +  6] & ((1 << 22) - 1)) << 4) | (Z[j +  7] << 26))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  5),
					(int) ((((Z[j +  7] >>>  6) & ((1 << 16) - 1))) |  (Z[j +  8] << 16))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  6),
					(int)  (((Z[j +  8] >>> 16) & ((1 <<  6) - 1))  | ((Z[j +  9] & ((1 << 22) - 1)) << 6) | (Z[j + 10] << 28))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  7),
					(int) ((((Z[j + 10] >>>  4) & ((1 << 18) - 1))) |  (Z[j + 11] << 18))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  8),
					(int)  (((Z[j + 11] >>> 14) & ((1 <<  8) - 1))  | ((Z[j + 12] & ((1 << 22) - 1)) << 8) | (Z[j + 13] << 30))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  9),
					(int) ((((Z[j + 13] >>>  2) & ((1 << 20) - 1))) |  (Z[j + 14] << 20))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 10),
					(int) ((((Z[j + 14] >>> 12) & ((1 << 10) - 1))) |  (Z[j + 15] << 10))
					
				);
				
				j += Integer.SIZE / 2;
				
			}
			
		}
		
		System.arraycopy (
				
			C, cOffset, signature, signatureOffset + parameter.n * parameter.d / Byte.SIZE, QTESLAParameter.HASH
			
		);
		
	}
	
	/*************************************************************************************************************************
	 * Description:	Encode Signature for Provably Secure qTESLA
	 * 
	 * @param		signature			Output Package Containing Signature
	 * @param		signatureOffset		Starting Point of the Output Package Containing Signature
	 * @param		C
	 * @param		cOffset
	 * @param		Z
	 * 
	 * @return		none
	 *************************************************************************************************************************/
	public void encodeSignature_MB (byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z) {
		
		int temp = 0;
		int j = 0;
		int maskb1 = ((1<<(parameter.bBit+1))-1);
		
		for (int i = 0; i < ( parameter.n*(parameter.bBit+1)/32); i+=11) {

			//pt[i+ 0] = ( ( t[j+ 0]        & ((1<<22)-1)) |  (t[j+ 1] << 22));
			temp = (   ( Z[j+0] & (( 1 << 22) -1 )) | (  Z[j+1] << 22  ));			
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 0), temp);
					
			// pt[i+ 1] = (((t[j+ 1] >> 10) & ((1<<12)-1)) |  (t[j+ 2] << 12));
			temp = (((Z[j+ 1] >> 10) & ((1<<12)-1)) |  (Z[j+ 2] << 12));
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 1), temp);
						
			// pt[i+ 2] = (((t[j+ 2] >> 20) & ((1<< 2)-1)) | ((t[j+ 3] & maskb1) <<  2) |  (t[j+ 4] << 24));
			temp = (((Z[j+ 2] >> 20) & ((1<< 2)-1)) | ((Z[j+ 3] & maskb1) <<  2) |  (Z[j+ 4] << 24));
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 2), temp);
					
			// pt[i+ 3] = (((t[j+ 4] >>  8) & ((1<<14)-1)) |  (t[j+ 5] << 14));
			temp = (((Z[j+ 4] >>  8) & ((1<<14)-1)) |  (Z[j+ 5] << 14));
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 3), temp);
					
			// pt[i+ 4] = (((t[j+ 5] >> 18) & ((1<< 4)-1)) | ((t[j+ 6] & maskb1) <<  4) |  (t[j+ 7] << 26));
			temp = (((Z[j+ 5] >> 18) & ((1<< 4)-1)) | ((Z[j+ 6] & maskb1) <<  4) |  (Z[j+ 7] << 26));
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 4), temp);
					
			// pt[i+ 5] = (((t[j+ 7] >>  6) & ((1<<16)-1)) |  (t[j+ 8] << 16));
			temp = (((Z[j+ 7] >>  6) & ((1<<16)-1)) |  (Z[j+ 8] << 16));
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 5), temp);
					
			// pt[i+ 6] = (((t[j+ 8] >> 16) & ((1<< 6)-1)) | ((t[j+ 9] & maskb1) <<  6) |  (t[j+10] << 28));
			temp = (((Z[j+ 8] >> 16) & ((1<< 6)-1)) | ((Z[j+ 9] & maskb1) <<  6) |  (Z[j+10] << 28));
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 6), temp);
					
			// pt[i+ 7] = (uint32_t)(((t[j+10] >>  4) & ((1<<18)-1)) |  (t[j+11] << 18));
			temp = (((Z[j+10] >>  4) & ((1<<18)-1)) |  (Z[j+11] << 18));
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 7), temp);
					
			// pt[i+ 8] =(((t[j+11] >> 14) & ((1<< 8)-1)) | ((t[j+12] & maskb1) <<  8) |  (t[j+13] << 30));
			temp = (((Z[j+11] >> 14) & ((1<< 8)-1)) | ((Z[j+12] & maskb1) <<  8) |  (Z[j+13] << 30));
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 8), temp);
					
			// pt[i+ 9] = (((t[j+13] >>  2) & ((1<<20)-1)) |  (t[j+14] << 20));
			temp = (((Z[j+13] >>  2) & ((1<<20)-1)) |  (Z[j+14] << 20));
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 9), temp);
						
			// pt[i+10] = (((t[j+14] >> 12) & ((1<<10)-1)) |  (t[j+15] << 10));  
			temp = (((Z[j+14] >> 12) & ((1<<10)-1)) |  (Z[j+15] << 10));			
			Common.store32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 10), temp);
			
			j += 16;
		}
		
		System.arraycopy (C, cOffset, signature, signatureOffset + parameter.n * (parameter.bBit + 1) / Byte.SIZE, 
				QTESLAParameter.HASH		);
		
	}
	
	
	public void encodeSignature (byte[] signature, int signatureOffset, byte[] C, int cOffset, long[] Z) {
		
		int j = 0;
		
		if (parameter.parameterSet == "qTESLA-P-I") {
			
			for (int i = 0; i < (parameter.n * parameter.d / Integer.SIZE); i += parameter.d / 2) {
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  0),
					(int)  (((Z[j +  0]         & ((1 << 22) - 1))) |  (Z[j +  1] << 22))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  1),
					(int) ((((Z[j +  1] >>> 10) & ((1 << 12) - 1))) |  (Z[j +  2] << 12))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  2),
					(int)  (((Z[j +  2] >>> 20) & ((1 <<  2) - 1))  | ((Z[j +  3] & ((1 << 22) - 1)) << 2) | (Z[j +  4] << 24))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  3),
					(int) ((((Z[j +  4] >>>  8) & ((1 << 14) - 1))) |  (Z[j +  5] << 14))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  4),
					(int)  (((Z[j +  5] >>> 18) & ((1 <<  4) - 1))  | ((Z[j +  6] & ((1 << 22) - 1)) << 4) | (Z[j +  7] << 26))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  5),
					(int) ((((Z[j +  7] >>>  6) & ((1 << 16) - 1))) |  (Z[j +  8] << 16))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  6),
					(int)  (((Z[j +  8] >>> 16) & ((1 <<  6) - 1))  | ((Z[j +  9] & ((1 << 22) - 1)) << 6) | (Z[j + 10] << 28))
					
				);
				
				Common.store32 (
					
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  7),
					(int) ((((Z[j + 10] >>>  4) & ((1 << 18) - 1))) |  (Z[j + 11] << 18))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  8),
					(int)  (((Z[j + 11] >>> 14) & ((1 <<  8) - 1))  | ((Z[j + 12] & ((1 << 22) - 1)) << 8) | (Z[j + 13] << 30))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i +  9),
					(int) ((((Z[j + 13] >>>  2) & ((1 << 20) - 1))) |  (Z[j + 14] << 20))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 10),
					(int) ((((Z[j + 14] >>> 12) & ((1 << 10) - 1))) |  (Z[j + 15] << 10))
					
				);
				
				j += Integer.SIZE / 2;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-III") {
			
			for (int i = 0; i < (parameter.n * parameter.d / Integer.SIZE); i += parameter.d / Byte.SIZE) {
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 0),
					(int)  (((Z[j + 0]         & ((1 << 24) - 1))) |  (Z[j + 1] << 24))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 1),
					(int) ((((Z[j + 1] >>>  8) & ((1 << 16) - 1))) |  (Z[j + 2] << 16))
					
				);
				
				Common.store32 (
						
					signature, signatureOffset + Integer.SIZE / Byte.SIZE * (i + 2),
					(int) ((((Z[j + 2] >>> 16) & ((1 <<  8) - 1))) |  (Z[j + 3] <<  8))
					
				);
				
				j += Byte.SIZE / 2;
				
			}
			
		}
		
		System.arraycopy (
				
			C, cOffset, signature, signatureOffset + parameter.n * parameter.d / Byte.SIZE, QTESLAParameter.HASH
			
		);
		
	}
	
	/***********************************************************************************************************************
	 * Description:	Decode Signature for Heuristic qTESLA
	 * 
	 * @param	C
	 * @param	Z
	 * @param	signature			Output Package Containing Signature
	 * @param	signatureOffset		Starting Point of the Output Package Containing Signature
	 * 
	 * @return	none
	 ***********************************************************************************************************************/
	public void decodeSignature (byte[] C, int[] Z, final byte[] signature, int signatureOffset) {
		
		int j = 0;
		
		if (parameter.parameterSet == "qTESLA-I" || parameter.parameterSet == "qTESLA-III-Size") {
			
			for (int i = 0; i < parameter.n; i += Integer.SIZE) {
				
				Z[i +  0] =	 (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  0)) <<  11) >> 11;
				
				Z[i +  1] =	((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  0)) >>> 21) |
							 (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  1)) <<  22) >> 11);
				
				Z[i +  2] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  1)) <<   1) >> 11;
				
				Z[i +  3] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  1)) >>> 31) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  2)) <<  12) >> 11);
				
				Z[i +  4] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  2)) >>> 20) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  3)) <<  23) >> 11);
				
				Z[i +  5] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  3)) <<   2) >> 11;
				
				Z[i +  6] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  3)) >>> 30) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  4)) <<  13) >> 11);
				
				Z[i +  7] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  4)) >>> 19) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  5)) <<  24) >> 11);
				
				Z[i +  8] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  5)) <<   3) >> 11;
				
				Z[i +  9] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  5)) >>> 29) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  6)) <<  14) >> 11);
				
				Z[i + 10] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  6)) >>> 18) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  7)) <<  25) >> 11);
				
				Z[i + 11] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  7)) <<   4) >> 11;
				
				Z[i + 12] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  7)) >>> 28) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  8)) <<  15) >> 11);
				
				Z[i + 13] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  8)) >>> 17) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  9)) <<  26) >> 11);
				
				Z[i + 14] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  9)) <<   5) >> 11;
				
				Z[i + 15] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  9)) >>> 27) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 10)) <<  16) >> 11);
				
				Z[i + 16] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 10)) >>> 16) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 11)) <<  27) >> 11);
				
				Z[i + 17] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 11)) <<   6) >> 11;
				
				Z[i + 18] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 11)) >>> 26) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 12)) <<  17) >> 11);
				
				Z[i + 19] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 12)) >>> 15) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 13)) <<  28) >> 11);
				
				Z[i + 20] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 13)) <<   7) >> 11;
				
				Z[i + 21] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 13)) >>> 25) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 14)) <<  18) >> 11);
				
				Z[i + 22] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 14)) >>> 14) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 15)) <<  29) >> 11);
				
				Z[i + 23] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 15)) <<   8) >> 11;
				
				Z[i + 24] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 15)) >>> 24) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 16)) <<  19) >> 11);
				
				Z[i + 25] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 16)) >>> 13) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 17)) <<  30) >> 11);
				
				Z[i + 26] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 17)) <<   9) >> 11;
				
				Z[i + 27] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 17)) >>> 23) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 18)) <<  20) >> 11);
				
				Z[i + 28] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 18)) >>> 12) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 19)) <<  31) >> 11);
				
				Z[i + 29] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 19)) <<  10) >> 11;
				
				Z[i + 30] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 19)) >>> 22) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 20)) <<  21) >> 11);
				
				Z[i + 31] =   Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 20)) >> 11;
				
				j += parameter.d;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-III-Speed") {
			
			for (int i = 0; i < parameter.n; i += Integer.SIZE / 2) {
				
				Z[i +  0] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  0)) <<  10) >> 10;
				
				Z[i +  1] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  0)) >>> 22) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  1)) <<  20) >> 10);
				
				Z[i +  2] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  1)) >>> 12) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  2)) <<  30) >> 10);
				
				Z[i +  3] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  2)) <<   8) >> 10;
				
				Z[i +  4] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  2)) >>> 24) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  3)) <<  18) >> 10);
				
				Z[i +  5] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  3)) >>> 14) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  4)) <<  28) >> 10);
				
				Z[i +  6] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  4)) <<   6) >> 10;
				
				Z[i +  7] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  4)) >>> 26) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  5)) <<  16) >> 10);
				
				Z[i +  8] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  5)) >>> 16) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  6)) <<  26) >> 10);
				
				Z[i +  9] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  6)) <<   4) >> 10;
				
				Z[i + 10] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  6)) >>> 28) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  7)) <<  14) >> 10);
				
				Z[i + 11] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  7)) >>> 18) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  8)) <<  24) >> 10);
				
				Z[i + 12] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  8)) <<   2) >> 10;
				
				Z[i + 13] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  8)) >>> 30) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  9)) <<  12) >> 10);
				
				Z[i + 14] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  9)) >>> 20) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 10)) <<  22) >> 10);
				
				Z[i + 15] =   Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 10)) >>  10;
				
				j += parameter.d / 2;
				
			}
			
		}
		
		System.arraycopy (signature, signatureOffset + parameter.n * parameter.d / Byte.SIZE, C, 0, QTESLAParameter.HASH);
		
	}
	
	/************************************************************************************************************************************
	 * Description:	Decode Signature for Provably Secure qTESLA
	 * 
	 * @param	C
	 * @param	Z
	 * @param	signature			Output Package Containing Signature
	 * @param	signatureOffset		Starting Point of the Output Package Containing Signature
	 * 
	 * @return	none
	 ************************************************************************************************************************************/
	public void decodeSignature_MB (byte[] C, int[] Z, final byte[] signature, int signatureOffset) {	
		int j = 0;		
	
		for (int i = 0; i < parameter.n; i += 16) {
		    Z[i+ 0] = (  Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 0)) << 10) >> 10;//
		    Z[i+ 1] =   (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 0)) >>> 22) | 
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 1)) << 20) >> 10); //
		    
		    Z[i+ 2] =   (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 1)) >>> 12) | //
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 2)) << 30) >> 10);
		    
		    Z[i+ 3] = (  Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 2)) <<  8) >> 10; //
		    Z[i+ 4] =   (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 2)) >>> 24) | 
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 3)) << 18) >> 10); //
		    Z[i+ 5] = (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 3)) >>> 14) | 
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 4)) << 28) >> 10);	    
		    Z[i+ 6] = (  Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 4)) <<  6) >> 10; //
		    Z[i+ 7] =   (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 4)) >>> 26) | 
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 5)) << 16) >> 10); //
		    Z[i+ 8] =   (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 5)) >>> 16) | 
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 6)) << 26) >> 10); //
		    Z[i+ 9] = (  Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 6)) <<  4) >> 10; //
		    Z[i+10] =   (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 6)) >>> 28) | 
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 7)) << 14) >> 10); // 
		    Z[i+11] =   (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 7)) >>> 18) | 
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 8)) << 24) >> 10); //
		    Z[i+12] = (  Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 8)) <<  2) >> 10; //
		    Z[i+13] =   (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 8)) >>> 30) | 
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 9)) << 12) >> 10); //
		    Z[i+14] =   (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 9)) >>> 20) | 
		    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +10)) << 22) >> 10); //
		    Z[i+15] =    Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +10)) >> 10;
		    j += 11;

		}
		
	    
	    /*System.out.println( Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 3)));
	    System.out.println( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 3)) >>> 1) );
	    
	    System.out.println( String.format("%32s", Integer.toBinaryString((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 3))))).replace(' ', '0'));
	    System.out.println( String.format("%32s", Integer.toBinaryString((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 3)) >>> 14))).replace(' ', '0'));
	    
	    System.out.println( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 4))));		    
	    System.out.println ( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 4)) << 28));		    
	    System.out.println( ( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 4)) << 28) >> 10));
	    System.out.println( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 3)) >> 14) | 
	    		( (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 4)) << 28) >> 10));
	    System.out.println( Z[i+ 5]);
	    System.exit(34);*/
		
		System.arraycopy (			
			signature, signatureOffset + parameter.n * (parameter.bBit+1)/ Byte.SIZE, C, 0, QTESLAParameter.HASH			
		);
		
	}
	
	
	public void decodeSignature (byte[] C, long[] Z, final byte[] signature, int signatureOffset) {
		
		int j = 0;
		
		if (parameter.parameterSet == "qTESLA-P-I") {
			
			for (int i = 0; i < parameter.n; i += Integer.SIZE / 2) {
				
				Z[i +  0] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  0)) <<  10) >> 10;
				
				Z[i +  1] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  0)) >>> 22) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  1)) <<  20) >> 10);
				
				Z[i +  2] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  1)) >>> 12) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  2)) <<  30) >> 10);
				
				Z[i +  3] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  2)) <<   8) >> 10;
				
				Z[i +  4] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  2)) >>> 24) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  3)) <<  18) >> 10);
				
				Z[i +  5] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  3)) >>> 14) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  4)) <<  28) >> 10);
				
				Z[i +  6] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  4)) <<   6) >> 10;
				
				Z[i +  7] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  4)) >>> 26) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  5)) <<  16) >> 10);
				
				Z[i +  8] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  5)) >>> 16) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  6)) <<  26) >> 10);
				
				Z[i +  9] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  6)) <<   4) >> 10;
				
				Z[i + 10] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  6)) >>> 28) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  7)) <<  14) >> 10);
				
				Z[i + 11] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  7)) >>> 18) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  8)) <<  24) >> 10);
				
				Z[i + 12] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  8)) <<   2) >> 10;
				
				Z[i + 13] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  8)) >>> 30) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  9)) <<  12) >> 10);
				
				Z[i + 14] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j +  9)) >>> 20) |
							((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 10)) <<  22) >> 10);
				
				Z[i + 15] =   Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 10)) >>  10;
				
				j += parameter.d / 2;
				
			}
			
		}
		
		if (parameter.parameterSet == "qTESLA-P-III") {
			
			for (int i = 0; i < parameter.n; i += Byte.SIZE / 2) {
				
				Z[i + 0] =  (Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 0)) <<   8) >> 8;
				
				Z[i + 1] = ((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 0)) >>> 24) & ((1 <<  8) - 1)) |
						   ((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 1)) <<  16) >> 8);
				
				Z[i + 2] = ((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 1)) >>> 16) & ((1 << 16) - 1)) |
						   ((Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 2)) <<  24) >> 8);
				
				Z[i + 3] =   Common.load32 (signature, signatureOffset + Integer.SIZE / Byte.SIZE * (j + 2)) >>   8;
				
				j += Byte.SIZE / 2 - 1;
				
			}
			
		}
		
		System.arraycopy (			
			signature, signatureOffset + parameter.n * parameter.d / Byte.SIZE, C, 0, QTESLAParameter.HASH
			
		);
		
	}
	
}