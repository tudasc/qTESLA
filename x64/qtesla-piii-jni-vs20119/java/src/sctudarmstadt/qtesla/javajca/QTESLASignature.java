/***********************************************************************************************
* qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
*
* qTESLA Signature Generation and Verification Implementing Signature Service Provider Interface
* 
* @author Yinhua Xu
************************************************************************************************/

package sctudarmstadt.qtesla.javajca;

import sctudarmstadt.qtesla.java.QTESLA;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

//import qTESLA.QTESLAParameterSpec;

public final class QTESLASignature extends SignatureSpi {
	/**
	 * qTESLA Parameter Set
	 */
	private String parameterSet;
	
	/**
	 * The Public Key of the Identity Whose Signature Will be Generated
	 */
	private QTESLAPublicKey publicKey;
	
	/**
	 * The Private Key of the Identity Whose Signature Will be Generated
	 */
	private QTESLAPrivateKey privateKey;
	
	/**
	 * The Source of Randomness
	 */
	private SecureRandom random;
	
	private byte[] message;
	
	private int messageOffset;
	
	private int[] messageLength;
	
	private QTESLA qTESLA;
	
	public QTESLASignature () {
		this.parameterSet = "qTESLA-P-III";
		this.qTESLA = new QTESLA (this.parameterSet);
	}
	
	/*************************************
	 * Getter of Parameter Set
	 * 
	 * @return	none
	 *************************************/
	public String getParameterSet () {
		
		return this.parameterSet;
		
	}
	
	/***************************************
	 * Getter of Secure Random Object
	 * 
	 * @return	none
	 ***************************************/
	public SecureRandom getSecureRandom () {
		
		return random;
	
	}

	/**************************************************
	 * Setter of Secure Random Object
	 * 
	 * @return	none
	 **************************************************/
	public void setSecureRandom (SecureRandom random) {
		
		this.random = random;
	
	}
	
	/**************************************
	 * Setter of QTESLA Object
	 * 
	 * @return	none
	 **************************************/
	public void setQTESLA (QTESLA qTESLA) {
		
		this.qTESLA = qTESLA;
		
	}
	
	@Override
	protected void engineInitSign (PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
		
		if (!(privateKey instanceof QTESLAPrivateKey)) {
			
			throw new InvalidKeyException ("The Input Key Is Not A qTESLA Private Key");
			
		}
		
		this.privateKey = (QTESLAPrivateKey) privateKey;
		this.parameterSet = ((QTESLAPrivateKey) privateKey).getAlgorithm();
		this.random = random;
		//this.qTESLA = new QTESLA (this.parameterSet);
		
	}
	
	@Override
	protected void engineInitSign (PrivateKey privateKey) throws InvalidKeyException {
		
		engineInitSign (privateKey, new SecureRandom ());
		
	}
	
	@Override
	protected void engineInitVerify (PublicKey publicKey) throws InvalidKeyException {
		
		if (!(publicKey instanceof QTESLAPublicKey)) {
			
			throw new InvalidKeyException ("The Input Key Is Not A qTESLA Public Key");
			
		}
		
		this.publicKey = (QTESLAPublicKey) publicKey;
		this.parameterSet = ((QTESLAPublicKey) publicKey).getAlgorithm();
		this.random = null;
		//this.qTESLA = new QTESLA (this.parameterSet);
		
	}
	
	@Override
	protected int engineSign (byte[] signature, int signatureOffset, int signatureLength) throws SignatureException {
		
		int[] lengthOfSignature	= new int[1];
		lengthOfSignature[0]	= signatureLength;
		
		if (this.parameterSet == "qTESLA-P-I" || this.parameterSet == "qTESLA-P-III") {
			
			try {
				//qTESLA.signPParallelVersion2 (signature, signatureOffset, lengthOfSignature, this.message, this.messageOffset, this.messageLength[0], this.privateKey.getEncoded(), this.random);
				//qTESLA.signPParallel (signature, signatureOffset, lengthOfSignature, this.message, this.messageOffset, this.messageLength[0], this.privateKey.getEncoded(), this.random);
				qTESLA.sign_MB(signature, signatureOffset, lengthOfSignature, this.message, this.messageOffset, this.messageLength[0], privateKey.getEncoded(), this.random);
			
			} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException
					| NoSuchPaddingException | ShortBufferException exception) {
				
				exception.printStackTrace();
			
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}			
		}
		
		else {
			System.err.println("Invalid parameterSet in QTESLASignature");
		}
		
		// Trunc to the Signature length, since C-Code appends whole message to signature array.
		byte[] c = new byte[ this.qTESLA.getQTESLAParameter().signatureSize ];
		System.arraycopy(signature, 0, c, 0, this.qTESLA.getQTESLAParameter().signatureSize);	
		signature = c;
		
		// Reset Signature
		this.message = new byte[0];
		this.messageLength[0] = 0;
		
		return 0;
		
	}
	
	@Override
	protected byte[] engineSign () throws SignatureException {
		
		byte[] signature = null;
		
		signature = new byte[qTESLA.getQTESLAParameter().signatureSize + this.messageLength[0]];
		
		engineSign (signature, 0, signature.length);
		
		return signature;
		
	}
	
	@Override
	protected boolean engineVerify (byte[] signature, int signatureOffset, int signatureLength) throws SignatureException {
		
		int success = 0;
		
		// Append the message tp the signature
		byte[] temp_bytes = new byte [qTESLA.getQTESLAParameter().signatureSize + this.message.length];		
		
		System.arraycopy(signature, 0, temp_bytes, 0, qTESLA.getQTESLAParameter().signatureSize);
		System.arraycopy(this.message, 0, temp_bytes, qTESLA.getQTESLAParameter().signatureSize, this.message.length);
		signature = temp_bytes;
		
		//System.out.println(Arrays.toString(signature));
		
		
		if (this.parameterSet == "qTESLA-P-I" || this.parameterSet == "qTESLA-P-III") {
			int messageLength[] = {0};
			for (int i=0; i < this.message.length; i++) {
				message[i] = 0;
			}
			
			
			
			success = qTESLA.verify_MB (this.message, 0, messageLength, signature, signatureOffset, signatureLength, this.publicKey.getEncoded());
	        //String s = new String(message, StandardCharsets.UTF_8);
	        //System.out.println("Output : " + s);
	        //System.out.flush();
		
		}
		
		else {
			System.err.println("Invalid parameterSet in QTESLASignature");
			success = -1;
		}
		
		if (success == 0) {
			
			return true;
			
		} else {
			
			return false;
			
		}
		
	}
	
	@Override
	protected boolean engineVerify (byte[] signature) throws SignatureException {
		
		return engineVerify (signature, 0, qTESLA.getQTESLAParameter().signatureSize + this.messageLength[0]);
		
	}
	
	@Override
	protected void engineUpdate (byte b) throws SignatureException {
		
		this.message = new byte[1];
		this.messageLength = new int[1];
		
		this.message[0] = b;
		this.messageOffset = 0;
		this.messageLength[0] = 1;
		
	}
	
	@Override
	protected void engineUpdate (byte[] byteArray, int byteArrayOffset, int byteArrayLength) throws SignatureException {
		
		this.message = new byte[byteArrayOffset + byteArrayLength];
		this.messageLength = new int[1];
		
		System.arraycopy (byteArray, byteArrayOffset, this.message, byteArrayOffset, byteArrayLength);
		this.messageOffset = byteArrayOffset;
		this.messageLength[0] = byteArrayLength;
		
	}
	
	@Override
	protected void engineUpdate (ByteBuffer byteBuffer) {
		
		int length = byteBuffer.remaining();
		this.message = new byte[length];
		this.messageLength = new int[1];
		
		byteBuffer.get (this.message, 0, length);
		this.messageOffset = 0;
		this.messageLength[0] = length;
		
	}
	
	@Override
	protected AlgorithmParameters engineGetParameters() {
		
		return null;
		
	}
	
	@Override
	protected void engineSetParameter (AlgorithmParameterSpec specification) throws InvalidAlgorithmParameterException {
		
		QTESLAParameterSpec qTESLAParameterSpec = (QTESLAParameterSpec) specification;
		
		this.parameterSet = qTESLAParameterSpec.getParameterSet();
		
	}

	@Override
	protected Object engineGetParameter (String parameter) throws InvalidParameterException {
		
		return null;
		
	}

	@Override
	protected void engineSetParameter(String parameter, Object value) throws InvalidParameterException {
		
	}
	
}