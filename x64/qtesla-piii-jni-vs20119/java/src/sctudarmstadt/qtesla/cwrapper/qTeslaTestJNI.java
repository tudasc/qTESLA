package sctudarmstadt.qtesla.cwrapper;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class qTeslaTestJNI {
	static {
		System.loadLibrary("qTeslaTest");
	}
	
	public qTeslaTestJNI () {
		nsthreads = 3;
	}
	
	public qTeslaTestJNI (int nt) {
		nsthreads = nt;
	}

	private int nsthreads;
	
	private native int checkQTesla (int runs, int signs, String in_message);
	
	private native int cryptoSignKeyPair( byte[] pk,  byte[] sk, int nt  );
	
	private native int cryptoSign( byte[] sing, long sig_len, byte[] mess, long mess_len, byte[] sk , int nt );
	
	private native int cryptoVerify( byte[] mess, long mess_len, byte[] sing, long sig_len, byte[] pk  );
	
	// getter for QTESLA Parameter
	private native int getPrivateKeySize();
	private native int getPublicKeySize();
	private native int getSignatureSize();
	
	// Methodes to AccessWrapper from Outside
	
	/**
	 * 
	 * @return
	 */
	public int getSignatureSize_Wrapper() {
		return getSignatureSize();
	}
	
	public int getPublicKeySize_Wrapper() {
		return getPublicKeySize();
	}
	
	public int getPrivateKeySize_Wrapper() {
		return getPrivateKeySize();
	}
	
	public byte[][] cryptoSignKeyPair_Wrapper( ) {
		byte[] pk = new byte [new qTeslaTestJNI().getPublicKeySize()];
		byte[] sk = new byte [new qTeslaTestJNI().getPrivateKeySize()];
		
		byte[][] arr = new byte[2][];
		arr[0] = pk;
		arr[1] = sk;

		new qTeslaTestJNI().cryptoSignKeyPair (pk, sk, nsthreads);	
		return arr;
	}
	
	public byte[] cryptoSign_Wrapper ( byte[] message, byte[] sk) {
		
		long message_len = message.length;
		long sign_len = new qTeslaTestJNI().getSignatureSize();
		// CAUTION: Have to cast to int since java does not support larger arrays. May case trouble?
		byte[] res = new byte[(int) (sign_len + message_len)];
		long res_len = 0;
		new qTeslaTestJNI().cryptoSign( res, res_len, message, message_len, sk, nsthreads );		
		return res;
	}
	
	public byte[] cryptoVerify_Wrapper ( byte[] signature, long message_len, byte[] pk) {
		// CAUTION: Have to cast to int since java does not support larger arrays. May case trouble?
		byte[] res = new byte[(int) (new qTeslaTestJNI().getSignatureSize() + message_len)];
		long res_len = message_len;
		
		int ret = new qTeslaTestJNI().cryptoVerify( res, res_len, signature, signature.length, pk  );
		
		// If C founds an error that is not found in Java, then the signature is manually corrupted here to make Java also fail
		if(ret!=0) {
			for(int i=0; i<res.length; i++) {
				res[i]=0;
			}
		}
			
		return res;
	}

	/*
	 * MAIN
	 */
	public static void mainO(String[] args) throws NoSuchAlgorithmException {
		
	int runs=1;
	int signs=1;
	String message="Hallo";

	if (args.length > 0) {
		try {
		    runs = Integer.parseInt(args[0]);
		} catch (NumberFormatException e) {
		    System.err.println("Argument" + args[0] + " must be an integer.");
		    runs=1;
		}

		try {
		    signs = Integer.parseInt(args[1]);
		} catch (NumberFormatException e) {
		    System.err.println("Argument" + args[1] + " must be an integer.");
		    signs=1;
		}

		try {
		    message = args[2];
		} catch (NumberFormatException e) {
		    System.err.println("Argument" + args[2] + " must be a string.");
		    message="Hallo";
		}
	}	
	// Check the JCA implementation
	new qTeslaTestJNI().checkQTesla (runs, signs, message);
	}
}
