package de.profhenry.sshsig.core.spi;

import java.security.PublicKey;

import de.profhenry.sshsig.core.SignatureAlgorithm;
import de.profhenry.sshsig.core.SshSignatureException;

/**
 * @author profhenry
 * @param <K> asdasdas
 */
public interface SigningBackend<K> {

	static class SigningResult {

		public PublicKey publicKey;

		public SignatureAlgorithm signatureAlgorithm;

		public byte[] signedContent;
	}

	SigningResult signData(K aKey, byte[] someDataToSign) throws SshSignatureException;

}
