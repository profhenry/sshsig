package de.profhenry.sshsig.core;

/**
 * @author profhenry
 */
public enum SignatureAlgorithm {

	SSH_DSS("SHA1WithDSA", "ssh-dss"),

	RSA_SHA2_512("SHA512WithRSA", "rsa-sha2-512"),

	RSA_SHA2_256("SHA256WithRSA", "rsa-sha2-256"),

	EdDSA("NONEwithECDSA", "ssh-ed25519"),

	ED25519("Ed25519", "ssh-ed25519");

	private final String signatureName;

	private final String nameUsedInSshProtocol;

	SignatureAlgorithm(String aSignatureName, String aNameUsedInSshProtocol) {
		signatureName = aSignatureName;
		nameUsedInSshProtocol = aNameUsedInSshProtocol;
	}

	public String getSignatureName() {
		return signatureName;
	}

	public String getNameUsedInSshProtocol() {
		return nameUsedInSshProtocol;
	}
}
