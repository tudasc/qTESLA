/***********************************************************************************************
 * qTESLA: An Efficient Post-Quantum Signature Scheme Based on the R-LWE Problem
 *
 * qTESLA Signature Generation and Verification Implementing Signature Service Provider Interface
 *
 * @author Yinhua Xu
 ************************************************************************************************/

package qTESLA;

import java.nio.ByteBuffer;
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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

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
        this.qTESLA = new QTESLA (this.parameterSet);

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
        this.qTESLA = new QTESLA (this.parameterSet);

    }

    @Override
    protected int engineSign (byte[] signature, int signatureOffset, int signatureLength) throws SignatureException {

        int[] lengthOfSignature	= new int[1];
        lengthOfSignature[0]	= signatureLength;

        if (this.parameterSet == "qTESLA-I" || this.parameterSet == "qTESLA-Speed" || this.parameterSet == "qTESLA-Size") {

            try {

                qTESLA.sign (signature, signatureOffset, lengthOfSignature, this.message, this.messageOffset, this.messageLength[0], this.privateKey.getEncoded(), this.random);

            } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException
                    | NoSuchPaddingException | ShortBufferException exception) {

                exception.printStackTrace();

            }

        }

        if (this.parameterSet == "qTESLA-P-I" || this.parameterSet == "qTESLA-P-III") {

            try {

                qTESLA.signP (signature, signatureOffset, lengthOfSignature, this.message, this.messageOffset, this.messageLength[0], this.privateKey.getEncoded(), this.random);

            } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException
                    | NoSuchPaddingException | ShortBufferException exception) {

                exception.printStackTrace();

            }

        }

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

        if (this.parameterSet == "qTESLA-I" || this.parameterSet == "qTESLA-III-Speed" || this.parameterSet == "qTESLA-III-Size") {

            success = qTESLA.verify (this.message, this.messageOffset, this.messageLength, signature, signatureOffset, signatureLength, this.publicKey.getEncoded());

        }

        if (this.parameterSet == "qTESLA-P-I" || this.parameterSet == "qTESLA-P-III") {

            success = qTESLA.verifyP (this.message, this.messageOffset, this.messageLength, signature, signatureOffset, signatureLength, this.publicKey.getEncoded());

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