package sctudarmstadt.qtesla.jca;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
//import java.security.Signature;
import java.security.SignatureException;

import sctudarmstadt.qtesla.cwrapper.qTeslaTestJNI;


public final class QTESLASignature extends Signature {
private
	byte[] _digist_buffer = {};
	
	private QTESLAPublicKey pub;
	private QTESLAPrivateKey priv;
	private qTeslaTestJNI jniwrap;
	
	private int priv_len; // Private Key Length
	private int pub_len; // Public Key Length
	private int sig_len; // Signative Length
	private int sign_threads; // Parallelity of C sign call
	
	public QTESLASignature() throws NoSuchAlgorithmException {
		super("QTESLA");		
	
		// Get the values for the underlying QTESLA implementation
		priv_len = new qTeslaTestJNI().getPrivateKeySize_Wrapper();
		pub_len = new qTeslaTestJNI().getPublicKeySize_Wrapper();
		sig_len = new qTeslaTestJNI().getSignatureSize_Wrapper();
		sign_threads = 1;
		this.jniwrap = new qTeslaTestJNI(sign_threads);
	}
	
	public void changeParallelity(int t) {
		sign_threads = t;
		this.jniwrap = new qTeslaTestJNI(sign_threads);
	}
	
	/**
	 * Initialize the object to prepare it to verify a digital signature. 
	 * If the public key does not support the correct algorithm or is otherwise corrupted, 
	 * an InvalidKeyException is thrown. 
	 */
	@Override
	protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
		try { 
			this.pub = (QTESLAPublicKey) publicKey; 
			} 
		
		catch (ClassCastException cce) 
		{ 
			throw new InvalidKeyException("Public key not from type QTESLAPublicKey"); 
		} 		
	}
	
	/**
	 * Initialize the object to prepare it to create a digital signature. 
	 * If the private key does not support the correct algorithm or is otherwise corrupted, 
	 * an InvalidKeyException is thrown.
	 */
	@Override
	protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
		try { 
			this.priv = (QTESLAPrivateKey) privateKey; 
			} 
		
		catch (ClassCastException cce) 
		{ 
			throw new InvalidKeyException("Private key not from type QTESLAPrivateKey"); 
		}
		
	}
	
	/*
	 * Add the given bytes to the data that is being accumulated for the signature. 
	 * These methods are called by the update() methods; they typically call the update() 
	 * method of a message digest held in the engine. If the engine has not been correctly 
	 * initialized, a SignatureException is thrown.
	 * 
	 * Actual hashing is done internally in QTESLA.sign in C
	 */
	@Override
	protected void engineUpdate(byte b) throws SignatureException {
		byte[] c = new byte[_digist_buffer.length + 1];
		System.arraycopy(_digist_buffer, 0, c, 0, _digist_buffer.length);
		c [_digist_buffer.length] = b;
		_digist_buffer = c;
	}
	
	@Override
	protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
		byte[] c = new byte[_digist_buffer.length + len];
		System.arraycopy(_digist_buffer, 0, c, 0, _digist_buffer.length);
		System.arraycopy(b, off, c, _digist_buffer.length, len);
		_digist_buffer = c;		
	}
	
	/**
	 * Create the signature based on the accumulated data. If there is an error in generating the signature, 
	 * a SignatureException is thrown.
	 */
	@Override
	protected byte[] engineSign() throws SignatureException {
		
		byte[] sigbytes = this.jniwrap.cryptoSign_Wrapper( _digist_buffer, priv.getBytesOfKey());		
		
		// Set the internal state to initialize
		_digist_buffer = new byte[0];
		
		// Trunc to the Signature length, since C-Code appends whole message to signature array.
		byte[] c = new byte[ this.sig_len ];
		System.arraycopy(sigbytes, 0, c, 0, this.sig_len);	
		
		return c;
	}
	
	/**
	 * Return an indication of whether or not the given signature matches the expected signature of the 
	 * accumulated data. If there is an error in validating the signature, a SignatureException is thrown. 
	 */
	@Override
	protected boolean engineVerify(byte[] sigbytes) throws SignatureException {
		// Check if the length is appropriate, otherwise it must be false
		int check_mess_len = this._digist_buffer.length;
		
		int inlen = sigbytes.length;
		
		// Trunc to the Signature length, since C-Code appends whole message to signature array.
		byte[] c = new byte[ this.sig_len ];
		System.arraycopy(sigbytes, 0, c, 0, this.sig_len);	
		
		// Append the message tp the signature
		byte[] temp_bytes = new byte [this.sig_len + check_mess_len];		
		
		System.arraycopy(sigbytes, 0, temp_bytes, 0, this.sig_len);
		System.arraycopy(_digist_buffer, 0, temp_bytes, this.sig_len, check_mess_len);
		sigbytes = temp_bytes;
		
		byte[] rec_message = this.jniwrap.cryptoVerify_Wrapper( sigbytes, check_mess_len, pub.getBytesOfKey());	
		
		// Check if messages are equal		
		try {
			for (int i=0; i < check_mess_len; i++) {		
				if(rec_message[i] != _digist_buffer[i]) {
					_digist_buffer = new byte[0];
					return false;
				}
			}
		}
		
		catch (Exception e) {
			throw new SignatureException();
		}

		_digist_buffer = new byte[0];
		return true;
	}
	
	/**
	 * Set the given parameters, which may be algorithm-specific. If this parameter does not apply to this algorithm, 
	 * this method should throw an InvalidParameterException.
	 */
	@Override
	protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
		throw new InvalidParameterException("No parameters");
		
	}
	
	/**
	 * Return the desired parameter, which is algorithm-specific. If the given parameter does not apply to this algorithm, 
	 * this method should throw an InvalidParameterException. 
	 */
	@Override
	protected Object engineGetParameter(String param) throws InvalidParameterException {
		throw new InvalidParameterException("No parameters");
	}
	
	public void engineReset() { 
		// Set the internal state to initialize
		_digist_buffer = new byte[0];		
	} 
}
