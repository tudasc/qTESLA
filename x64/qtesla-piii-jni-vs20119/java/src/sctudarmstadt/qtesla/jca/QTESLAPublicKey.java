package sctudarmstadt.qtesla.jca;

import java.security.PublicKey;

public final class QTESLAPublicKey extends QTESLAKey implements PublicKey {
	public QTESLAPublicKey () {
		super();
	}
	
	public QTESLAPublicKey (byte[] _data) {
		super(_data);
	}
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -5428189240901941082L;	


    /**
     * Returns the standard algorithm name for this key. For
     * example, "DSA" would indicate that this key is a DSA key.
     * See the key related sections (KeyFactory, KeyGenerator,
     * KeyPairGenerator, and SecretKeyFactory) in the <a href=
     * "{@docRoot}/../specs/security/standard-names.html">
     * Java Security Standard Algorithm Names Specification</a>
     * for information about standard key algorithm names.
     *
     * @return the name of the algorithm associated with this key.
     */
	@Override
	public String getAlgorithm() {
		return "qTESLA-P-III";
	}

    /**
     * Returns the name of the primary encoding format of this key,
     * or null if this key does not support encoding.
     * The primary encoding format is
     * named in terms of the appropriate ASN.1 data format, if an
     * ASN.1 specification for this key exists.
     * For example, the name of the ASN.1 data format for public
     * keys is <I>SubjectPublicKeyInfo</I>, as
     * defined by the X.509 standard; in this case, the returned format is
     * {@code "X.509"}. Similarly,
     * the name of the ASN.1 data format for private keys is
     * <I>PrivateKeyInfo</I>,
     * as defined by the PKCS #8 standard; in this case, the returned format is
     * {@code "PKCS#8"}.
     *
     * @return the primary encoding format of the key.
     */
	@Override
	public String getFormat() {
		return null;
	}

    /**
     * Returns the key in its primary encoding format, or null
     * if this key does not support encoding.
     *
     * @return the encoded key, or null if the key does not support
     * encoding.
     */


}
