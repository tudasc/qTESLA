/******************************************************************************
* qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
*
* Heuristic and Provably Secure qTESLA Parameters
* 
* @author Yinhua Xu
*******************************************************************************/

package sctudarmstadt.qtesla.java;

public final class QTESLAParameter {
	
	/**
	 * Size of A Random Number (in Byte)
	 */
	public static final int RANDOM	= 32;
	
	/**
	 * Size of A Seed (in Byte)
	 */
	public static final int SEED	= 32;
	
	/**
	 * Size of Hash Value C (in Byte) in the Signature Package
	 */
	public static final int HASH	= 32;
	
	/**
	 * Size of Hashed Message
	 */
	public static final int MESSAGE = 40;
	
	/**
	 * One of Five Heuristic and Provably Secure Security Categories
	 */
	public String parameterSet;
	
	/** 
	 * Dimension, (Dimension - 1) is the Polynomial Degree
	 */
	public int n;
	
	/**
	 * nLogarithm = Logarithm (n) / Logarithm (2)
	 */
	public int nLogarithm;
	
	/**
	 * Modulus
	 */
	public int q;
	
	/**
	 * qLogarihm = Ceil (Logarithm (q) / Logarithm (2))
	 */
	public int qLogarithm;
	
	public long qInverse;
	
	/**
	 * b Determines the Interval the Randomness is Chosen in During Signature Generation
	 */
	public int b;
	
	/**
	 * b = 2 ^ bBit - 1
	 */
	public int bBit;
	
	public int sBit;
	
	/**
	 * Number of Ring-Learning-With-Errors Samples
	 */
	public int k;
	
	/** 
	 * Number of Non-Zero Entries of Output Elements of Encoding
	 */
	public int h;
	
	/** 
	 * Number of Rounded Bits
	 */
	public int d;
	
	/** 
	 * Bound in Checking Error Polynomial (Rejection)
	 */
	public int boundE;
	
	/** 
	 * Bound in Checking Secret Polynomial (U)
	 */
	public int boundS;
	
	public int paulBarrettMultiplier;
	
	public int paulBarrettDivisor;
	
	/**
	 * The Number of Blocks Requested in the First Extendable-Output Function Call
	 */
	public int generateA;
	
	public int inverseNumberTheoreticTransform;
	
	public int r;
	
	/** 
	 * Size of the Signature Package (Z, C) (in Byte)
	 * Z is A Polynomial Bounded by B and C is the Output of A Hashed String
	 */
	public int signatureSize;
	
	/** 
	 * Size of the Public Key (in Byte) Containing seedA and Polynomial T
	 */
	public int publicKeySize;
	
	/** 
	 * Size of the Private Key (in Byte) Containing Polynomials (Secret Polynomial and Error Polynomial) and Seeds (seedA and seedY)
	 */
	public int privateKeySize;
	
	public int messageLength;
	
	/*******************************************************
	 * qTESLA Parameter Constructor
	 * 
	 * @param parameterSet		qTESLA Parameter Set
	 *******************************************************/
	public QTESLAParameter (String parameterSet) {
		
		if(parameterSet!=null)
			this.parameterSet = parameterSet;
		else {
			this.parameterSet = "qTESLA-P-III";			
		}

		/*if (parameterSet == "qTESLA-P-I") {
			
			this.n = 1024;
			this.nLogarithm = 10;
			this.q = 485978113;
			this.qLogarithm = 29;
			this.qInverse = 3421990911L;
			this.b = 2097151;
			this.bBit = 21;
			this.sBit = 8;
			this.k = 4;
			this.h = 25;
			this.d = 22;
			this.boundE = 554;
			this.boundS = 554;
			this.paulBarrettMultiplier = 1;
			this.paulBarrettDivisor = 29;
			this.generateA = 108;
			this.inverseNumberTheoreticTransform = 472064468;
			this.r = 0;
			privateKeySize = this.n + this.n * this.k + SEED * 2;
			
		} */
		
		
		/**
		 * 		else if (parameterSet == "qTESLA-P-III") {
			
			this.n = 2048; //
			this.nLogarithm = 11; //
			this.q = 1129725953; //856145921; // ;
			this.qLogarithm = 31; // 30; // 
			this.qInverse = 861290495L; // 587710463L; //;
			this.b = 8388607; // 2097151; //
			this.bBit = 23; // 21; //
			this.sBit = 8; //
			this.k = 5; //
			this.h = 40; //
			this.d = 24; //
			this.boundE = 901; //
			this.boundS = 901; //
			this.paulBarrettMultiplier = 15; // 5; // 
			this.paulBarrettDivisor = 34; // 32; // 
			
			this.generateA = 180; // ?
			this.inverseNumberTheoreticTransform = 851423148; // ?
			this.r = 0; // 14237691; // 0
			privateKeySize = this.n + this.n * this.k + SEED * 2;
			
		} 
		 */
		
		if (this.parameterSet == "qTESLA-P-III") {
			
			//PARAM_SIGMA 8.5
			//#define PARAM_SIGMA_E PARAM_SIGMA
			
			this.n = 2048; // 2048;
			this.nLogarithm = 11; // 11; 
			this.q = 856145921; // 1129725953;
			this.qLogarithm = 30; // 31; // 
			this.b = 2097151; // 8388607;
			this.bBit = 21; // 23;
			this.sBit = 8; // 8;
			this.k = 5; // 5;
			this.h = 40; // 40;
			this.d = 24; // 24;
			this.generateA = 180; // 180;
		
			this.boundE = 901; //
			this.boundS = 901; //
			privateKeySize = ((this.k+1)*this.sBit*this.n/8 + 2*SEED + MESSAGE); // C++-way, same value
			
			this.qInverse = 587710463L;// 861290495L;					

			this.paulBarrettMultiplier = 5; // 15;
			this.paulBarrettDivisor = 32; // 34; 
			
			
			this.inverseNumberTheoreticTransform = 513161157; // 851423148; // This is PARAM_R2_INVN
			//this.r = 0; // 14237691; // Is it used at all? Seems not
			
			this.messageLength = 40;
			
			
		} 
		
		else {
			System.err.println("Wrong Parameter for QTESLA called!");
			this.parameterSet = null;
			this.n = 1;
			this.q = 2;
			this.qLogarithm = 0;
			this.qInverse = 1;
			this.b = 0;
			this.bBit = 0;
			this.sBit = 0;
			this.k = 1;
			this.h = 0;
			this.d = 1;
			this.boundE = 0;
			this.boundS = 0;
			this.paulBarrettMultiplier = 1;
			this.paulBarrettDivisor = 1;
			this.generateA = 1;
			this.inverseNumberTheoreticTransform = 1;
			this.r = 0;
			this.privateKeySize = 1;
			
		}
		signatureSize = ((n * (bBit+1)+7)/8 + HASH);	
		publicKeySize = (n * k * qLogarithm + 7) / 8 + SEED;		
	}
	
}