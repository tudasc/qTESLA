/******************************************************************************
 * qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
 *
 * Generated qTESLA Public Key
 *
 * @author Yinhua Xu
 *******************************************************************************/

package qTESLA;

import java.security.PublicKey;
import java.util.Arrays;

public final class QTESLAPublicKey implements PublicKey {

    /**
     * The Class Fingerprint That is Set to Indicate Serialization Compatibility with
     * A previous Version of the Class
     */
    private static final long serialVersionUID = -8146247554834846930L;

    /**
     * qTESLA Parameter Set
     */
    private String parameterSet;

    /**
     * Text of the qTESLA Public Key
     */
    private byte[] publicKey;

    public QTESLAPublicKey (String parameterSet) {

        this.parameterSet = parameterSet;
        QTESLAParameter parameter = new QTESLAParameter (parameterSet);
        publicKey = new byte[parameter.publicKeySize];
        Arrays.fill (publicKey, (byte) 0);

    }

    public void setparameterSet (String parameterSet) {

        this.parameterSet = parameterSet;

    }

    @Override
    public String getAlgorithm () {

        return this.parameterSet;

    }

    @Override
    public byte[] getEncoded () {

        return publicKey;
    }

    public void setPublicKey (byte[] publicKey) {

        System.arraycopy (publicKey, 0, this.publicKey, 0, publicKey.length);

    }

    @Override
    public String getFormat () {

        return "X.509";

    }

}