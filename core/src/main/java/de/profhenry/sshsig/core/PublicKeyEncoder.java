package de.profhenry.sshsig.core;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author profhenry
 */
public class PublicKeyEncoder {

	/**
	 * The logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(SshSignatureGenerator.class);

	private static final String SSH_DSS = "ssh-dss";

	private static final String SSH_RSA = "ssh-rsa";

	private static final String SSH_ED25519 = "ssh-ed25519";

	public byte[] encodePublicKey(PublicKey aPublicKey) throws SshSignatureException {
		if (aPublicKey instanceof DSAPublicKey) {
			return encodeDsaPublicKey((DSAPublicKey) aPublicKey);
		}
		if (aPublicKey instanceof RSAPublicKey) {
			return encodeRsaPublicKey((RSAPublicKey) aPublicKey);
		}
		if ("EdDSA".equals(aPublicKey.getAlgorithm())) {
			return encodeEd25519PublicKey(aPublicKey);
		}
		if ("Ed25519".equals(aPublicKey.getAlgorithm())) {
			return encodeEd25519PublicKey(aPublicKey);
		}
		throw new SshSignatureException("Could not encode public key (" + aPublicKey.getClass().getName() + ")!");
	}

	/**
	 * Encodes a DSA public key.
	 * <p>
	 * https://www.rfc-editor.org/rfc/rfc4253#page-14
	 * <p>
	 * 
	 * @param aDsaPublicKey the DSA public key
	 * @return the encoded DSA public key
	 */
	protected byte[] encodeDsaPublicKey(DSAPublicKey aDsaPublicKey) {
		SshBuffer tBuffer = new SshBuffer();
		tBuffer.appendString(SSH_DSS);
		tBuffer.appendBigInteger(aDsaPublicKey.getParams().getP());
		tBuffer.appendBigInteger(aDsaPublicKey.getParams().getQ());
		tBuffer.appendBigInteger(aDsaPublicKey.getParams().getG());
		tBuffer.appendBigInteger(aDsaPublicKey.getY());
		return tBuffer.toByteArray();
	}

	/**
	 * Encodes a RSA public key.
	 * <p>
	 * https://www.rfc-editor.org/rfc/rfc4253#page-15
	 * <p>
	 * https://www.rfc-editor.org/rfc/rfc3447#page-44
	 * 
	 * @param aRsaPublicKey the RSA public key
	 * @return the encoded RSA public key
	 */
	protected final byte[] encodeRsaPublicKey(RSAPublicKey aRsaPublicKey) {
		SshBuffer tBuffer = new SshBuffer();
		tBuffer.appendString(SSH_RSA);
		tBuffer.appendBigInteger(aRsaPublicKey.getPublicExponent());
		tBuffer.appendBigInteger(aRsaPublicKey.getModulus());
		return tBuffer.toByteArray();
	}

	protected byte[] encodeEd25519PublicKey(PublicKey aPublicKey) throws SshSignatureException {
		if ("X.509".equals(aPublicKey.getFormat())) {
			SshBuffer tBuffer = new SshBuffer();
			tBuffer.appendString(SSH_ED25519);
			tBuffer.appendByteArray(aPublicKey.getEncoded(), 12, 32);
			return tBuffer.toByteArray();
		}
		throw new SshSignatureException("Mööp");
	}
}
