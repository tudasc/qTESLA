/******************************************************************************
* qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
*
* Registration of qTESLA Provider Version 2.4
* 
* @author Yinhua Xu
*******************************************************************************/

package sctudarmstadt.qtesla.javajca;

import java.security.Provider;

public final class QTESLAJavaProvider extends Provider {

	/**
	 * Serial Version User Identity
	 */
	private static final long serialVersionUID = 8348304362615727658L;
	
	public QTESLAJavaProvider() {
		
		// 2.4 to string sometime
		super (
				
			"QTESLAJavaProvider",
			2.4,
			"qTESLA Provider 2.4, An Efficient and Post-Quantum Secure Lattice-Based Signature Scheme"
			
		);
		
		put ("KeyPairGenerator.QTESLA", QTESLAKeyPairGenerator.class.getName());
		put ("Signature.QTESLA", QTESLASignature.class.getName());
	
	}
	
}