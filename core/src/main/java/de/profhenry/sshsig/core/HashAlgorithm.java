package de.profhenry.sshsig.core;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Defines the hash algorithms supported by SSH signature generation.
 * <p>
 * According to <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig">the SSH spec</a> the
 * following are hash algorithms are supported:
 * <ul>
 * <li>SHA-256</li>
 * <li>SHA-512 (default)</li>
 * </ul>
 * 
 * @author profhenry
 */
public enum HashAlgorithm {

	SHA_256("SHA-256", "sha256"),

	SHA_512("SHA-512", "sha512");

	/**
	 * Name for the corresponding JCA message digest.
	 */
	private final String messageDigestName;

	/**
	 * Name used in the SSH wire protocol.
	 */
	private final String nameUsedInSshProtocol;

	private HashAlgorithm(String aMessageDigestName, String aNameUsedInSshProtocol) {
		messageDigestName = aMessageDigestName;
		nameUsedInSshProtocol = aNameUsedInSshProtocol;
	}

	public MessageDigest createMessageDigestInstance() throws SshSignatureException {
		try {
			return MessageDigest.getInstance(messageDigestName);
		} catch (NoSuchAlgorithmException exc) {
			throw new SshSignatureException("Hash algorithm " + this + " not available!", exc);
		}
	}

	public String getNameUsedInSshProtocol() {
		return nameUsedInSshProtocol;
	}
}
