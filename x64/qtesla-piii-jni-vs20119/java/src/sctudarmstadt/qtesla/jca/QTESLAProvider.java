package sctudarmstadt.qtesla.jca;

import java.security.Provider;

public final class QTESLAProvider extends Provider {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5645029080181560568L;
	public QTESLAProvider() {
		// 0.2 to string sometime
		super("QTESLAProvider", 
				0.2, 
				"The QTESLA provider of TU Darmstadt implementing QTESLA post-quantum signature scheme.");
		
		put("Signature.QTESLA", "sctudarmstadt.qtesla.jca.QTESLASignature");
		put("KeyPairGenerator.QTESLA", "sctudarmstadt.qtesla.jca.QTESLAKeyPairGenerator");
	}

}
