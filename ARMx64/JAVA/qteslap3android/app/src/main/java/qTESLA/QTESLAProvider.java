/******************************************************************************
 * qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
 *
 * Registration of qTESLA Provider Version 2.4
 *
 * @author Yinhua Xu
 *******************************************************************************/

package qTESLA;

import java.security.Provider;

public class QTESLAProvider extends Provider {

    /**
     * Serial Version User Identity
     */
    private static final long serialVersionUID = 8348304362615727658L;

    protected QTESLAProvider() {

        super (

                "qTESLAProvider",
                2.4,
                "qTESLA Provider 2.4, An Efficient and Post-Quantum Secure Lattice-Based Signature Scheme"

        );

        put ("KeyPairGenerator.QTESLAKeyPairGenerator", QTESLAKeyPairGenerator.class.getName());
        put ("Signature.QTESLASignature", QTESLASignature.class.getName());

    }

}