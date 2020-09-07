package sctudarmstadt.qtesla.tests;


import sctudarmstadt.qtesla.cwrapper.qTeslaTestJNI;
import sctudarmstadt.qtesla.jca.QTESLAKeyPairGenerator;
import sctudarmstadt.qtesla.jca.QTESLAPrivateKey;
import sctudarmstadt.qtesla.jca.QTESLAPublicKey;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class MainTest {
	private static int KeyGenWrapperTest() {
		qTeslaTestJNI jniwrap = new qTeslaTestJNI();
		byte[][] keys = jniwrap.cryptoSignKeyPair_Wrapper();
		
		System.out.println("PK byte array: " + Arrays.toString(keys[0]));
		System.out.println("SK byte array: " + Arrays.toString(keys[1]));		
		return 0;
	}
	
	private static int QTESLAKeyGeneratorTest() {
		QTESLAKeyPairGenerator gen = new QTESLAKeyPairGenerator();
		gen.generateKeyPair();
		return 0;
	}
	
	private static int SignWrapperTest() {
		qTeslaTestJNI jniwrap = new qTeslaTestJNI();
		
		QTESLAKeyPairGenerator gen = new QTESLAKeyPairGenerator();
		KeyPair kp = gen.generateKeyPair();
		
		// Test to sign a message		
		byte[] mesbyte = new byte[59];
		for (int i=0; i<59; i++) {
			mesbyte[i] = (byte)i;
		}
		
		QTESLAPrivateKey qtpriv = (QTESLAPrivateKey) kp.getPrivate();		
		byte[] sigbyte = jniwrap.cryptoSign_Wrapper( mesbyte, qtpriv.getBytesOfKey());
		System.out.println("Signature byte array: " + Arrays.toString(sigbyte));
		
		return 0;
	}
	
	private static int SignVerifyWrapperTest() {
		qTeslaTestJNI jniwrap = new qTeslaTestJNI();
		
		QTESLAKeyPairGenerator gen = new QTESLAKeyPairGenerator();
		KeyPair kp = gen.generateKeyPair();
		
		// Sign a message		
		byte[] mesbyte = new byte[59];
		for (int i=0; i<59; i++) {
			mesbyte[i] = (byte)i;
		}
		
		QTESLAPrivateKey qtpriv = (QTESLAPrivateKey) kp.getPrivate();	
		byte[] sigbyte = jniwrap.cryptoSign_Wrapper( mesbyte, qtpriv.getBytesOfKey());

		// Verify the message	
		QTESLAPublicKey qtpub = (QTESLAPublicKey) kp.getPublic();
		byte[] rec_message = jniwrap.cryptoVerify_Wrapper( sigbyte, 59, qtpub.getBytesOfKey());
		
		System.out.println("Verfied message byte array: " + Arrays.toString(rec_message));
		return 0;
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException {
		KeyGenWrapperTest();
		QTESLAKeyGeneratorTest();
		
		SignWrapperTest();
		
		SignVerifyWrapperTest();

		qTeslaTestJNI.mainO(args);
	}
}
