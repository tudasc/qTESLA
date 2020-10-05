package sctudarmstadt.qtesla.jca;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import sctudarmstadt.qtesla.cwrapper.*;

public class QTESLAKeyPairGenerator extends KeyPairGenerator {
	public QTESLAKeyPairGenerator () {
		super("QTESLA");
	}
	
	private QTESLAKeyPair generateKQTESLAeyPair() {
		qTeslaTestJNI jniwrap = new qTeslaTestJNI();
		byte[][] keys = jniwrap.cryptoSignKeyPair_Wrapper();
		
		QTESLAKeyPair _key_pair = new QTESLAKeyPair();
		_key_pair.setPublicKey(  new QTESLAPublicKey(keys[0]) );
		_key_pair.setPrivateKey(  new QTESLAPrivateKey(keys[1]) );		
		return _key_pair;
	}


/**
 * Both things are not used for qtesla!
 */
	@Override
	public void initialize(int keysize, SecureRandom random) {
		return;
		
	}
	
	public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
		return;
	}


	@Override
	public KeyPair generateKeyPair() {
		QTESLAKeyPair qtpair = generateKQTESLAeyPair();
		
		KeyPair kpair = new KeyPair ( qtpair.getPublicKey(), qtpair.getPrivateKey()        );
		return kpair;
	}
}
