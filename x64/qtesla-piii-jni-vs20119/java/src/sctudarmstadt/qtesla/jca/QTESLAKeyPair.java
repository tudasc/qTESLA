package sctudarmstadt.qtesla.jca;

import java.security.PrivateKey;
import java.security.PublicKey;

public class QTESLAKeyPair {
	private QTESLAPublicKey pubkey;
	private QTESLAPrivateKey seckey; 
	
	public QTESLAKeyPair () {
		
	}

	public PrivateKey getPrivate() {
		return (PrivateKey)this.seckey;
	}

	public PublicKey getPublic() {
		return (PublicKey)this.pubkey;
	}
	
	
	public QTESLAPrivateKey getPrivateKey() {
		return this.seckey;
	}

	public QTESLAPublicKey getPublicKey() {
		return this.pubkey;
	}
	
	public void setPublicKey (QTESLAPublicKey k) {
		this.pubkey = k;
		return;
	}
	
	public void setPrivateKey (QTESLAPrivateKey k) {
		this.seckey = k;
		return;
	}
}
