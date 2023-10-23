package de.profhenry.sshsig;

/**
 * @author profhenry
 */
public enum HashAlgorithm {

	SHA_512("SHA-512", "sha512"),

	SHA_256("SHA-256", "sha256");

	private final String messageDigestName;

	private final String nameUsedInSshProtocol;

	HashAlgorithm(String aMessageDigestName, String aNameUsedInSshProtocol) {
		messageDigestName = aMessageDigestName;
		nameUsedInSshProtocol = aNameUsedInSshProtocol;
	}

	public String getMessageDigestName() {
		return messageDigestName;
	}

	public String getNameUsedInSshProtocol() {
		return nameUsedInSshProtocol;
	}
}
