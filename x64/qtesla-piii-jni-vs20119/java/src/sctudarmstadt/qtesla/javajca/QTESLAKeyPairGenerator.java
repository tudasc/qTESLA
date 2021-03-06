/*************************************************************************************
* qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
*
* qTESLA Key Pair Generator Implementing Key Pair Generator Service Provider Interface
* 
* @author Yinhua Xu
**************************************************************************************/

package sctudarmstadt.qtesla.javajca;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

//import qTESLA.QTESLAPrivateKey;
//import qTESLA.QTESLAParameterSpec;
import sctudarmstadt.qtesla.java.QTESLA;

public final class QTESLAKeyPairGenerator extends KeyPairGeneratorSpi {

	/**
	 * qTESLA Parameter Set
	 */
	private String parameterSet;
	
	/**
	 * The Source of Randomness
	 */
	private SecureRandom random;
	
	private QTESLA qTESLA;
	
	/*
	 * Default is always "qTESLA-P-III". Otherwise, initialize must be called.
	 */
	public QTESLAKeyPairGenerator () {
		this.parameterSet = "qTESLA-P-III";
		this.qTESLA = new QTESLA (this.parameterSet);		
	}
	
	/**************************************
	 * Setter of Parameter Set
	 * 
	 * @return	none
	 **************************************/
	public void setQTESLA (QTESLA qTESLA) {
		
		this.qTESLA = qTESLA;
		
	}
	
	@Override
	public KeyPair generateKeyPair() {
		
		QTESLAPrivateKey qTESLAPrivateKey	= new QTESLAPrivateKey (this.parameterSet);
		QTESLAPublicKey qTESLAPublicKey		= new QTESLAPublicKey (this.parameterSet);
		
		byte[] privateKey	= qTESLAPrivateKey.getEncoded();
		byte[] publicKey 	= qTESLAPublicKey.getEncoded();
		this.random			= new SecureRandom();
		
		if(this.parameterSet == null)
			this.parameterSet = "qTESLA-P-III";
		
		if (
				this.parameterSet == "qTESLA-I" ||
				this.parameterSet == "qTESLA-III-Speed" ||
				this.parameterSet == "qTESLA-III-Size"
		
		) {
				
			try {
				
				qTESLA.generateKeyPair_MB (publicKey, privateKey, random);
			
			} catch (
				
				BadPaddingException |
				IllegalBlockSizeException |
				InvalidKeyException |
				NoSuchAlgorithmException |
				NoSuchPaddingException |
				ShortBufferException exception
			
			) {
				
				exception.printStackTrace();
			
			}
			
		}
		
		if (this.parameterSet == "qTESLA-P-I" || this.parameterSet == "qTESLA-P-III") {
			
			try {
				
				qTESLA.generateKeyPair_MB (publicKey, privateKey, random);
			
			} catch (
					
				BadPaddingException |
				IllegalBlockSizeException |
				InvalidKeyException |
				NoSuchAlgorithmException |
				NoSuchPaddingException |
				ShortBufferException exception
			
			) {
				
				exception.printStackTrace();
			}
			
		}
		
		else {
			System.err.println("No supported parameterSet for QTESLA in QTESLAKeyPairGenerator");
		}
		
		qTESLAPrivateKey.setPrivateKey (privateKey);
		qTESLAPublicKey.setPublicKey (publicKey);
		
		return new KeyPair (qTESLAPublicKey, qTESLAPrivateKey);
		
		
		//DEBUG: Hardcoded Keys
		
	}

	
	@Override
	public void initialize(int keysize, SecureRandom random) {
		
		try {
				
			throw new InvalidKeyException("A Single Key Size is not Supported by qTESLA Algorithm");
			
		} catch (InvalidKeyException exception) {
				
			exception.printStackTrace();
			
		}
			
	}
	
	@Override
	public void initialize (AlgorithmParameterSpec specification, SecureRandom random) 
			
		throws InvalidAlgorithmParameterException {
		
		if (! (specification instanceof QTESLAParameterSpec)) {
			
			throw new InvalidAlgorithmParameterException ("Parameters Do Not Belong To qTESLA");
			
		}
		
		QTESLAParameterSpec qTESLAParameterSpec = (QTESLAParameterSpec) specification;
		
		this.parameterSet = qTESLAParameterSpec.getParameterSet();
		this.random = random;
		this.qTESLA = new QTESLA (this.parameterSet);
		
	}
	
}