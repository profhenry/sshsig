package de.profhenry.sshsig.core;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.profhenry.sshsig.core.spi.SigningBackend;

/**
 * A {@link SigningBackend} using Java Cryptography Architecture (JCA).
 * <p>
 * For signing you need to specify a {@link KeyPair}, the {@link PrivateKey} is required for the actual signing process,
 * the {@link PublicKey} is required because it gets embedded into the SSH signature.
 * <p>
 * The SSH
 * 
 * @author profhenry
 */
public class JcaSingingBackend implements SigningBackend<KeyPair> {

	private static final Logger LOGGER = LoggerFactory.getLogger(JcaSingingBackend.class);

	@Override
	public SigningResult signData(KeyPair aKeyPair, byte[] someDataToSign) throws SshSignatureException {
		PrivateKey tPrivateKey = aKeyPair.getPrivate();
		PublicKey tPublicKey = aKeyPair.getPublic();

		LOGGER.debug("PrivateKey: {} {} ({})",
				tPrivateKey.getAlgorithm(),
				tPrivateKey.getFormat(),
				tPrivateKey.getClass().getName());
		LOGGER.debug("PublicKey: {} {} ({})",
				tPublicKey.getAlgorithm(),
				tPublicKey.getFormat(),
				tPublicKey.getClass().getName());

		if (!tPrivateKey.getAlgorithm().equals(tPublicKey.getAlgorithm())) {
			throw new SshSignatureException("Mööp");
		}
		if ("DSA".equals(tPrivateKey.getAlgorithm())) {
			SignatureAlgorithm tSignatureAlgorithm = SignatureAlgorithm.SSH_DSS;

			return sign1(tPrivateKey, tPublicKey, tSignatureAlgorithm, someDataToSign);
		}
		if ("RSA".equals(tPrivateKey.getAlgorithm())) {
			SignatureAlgorithm tSignatureAlgorithm = SignatureAlgorithm.RSA_SHA2_512;

			return sign0(tPrivateKey, tPublicKey, tSignatureAlgorithm, someDataToSign);
		}
		if ("EdDSA".equals(tPrivateKey.getAlgorithm())) {
			SignatureAlgorithm tSignatureAlgorithm = SignatureAlgorithm.ED25519;
			return sign0(tPrivateKey, tPublicKey, tSignatureAlgorithm, someDataToSign);
		}
		if ("Ed25519".equals(tPrivateKey.getAlgorithm())) {
			SignatureAlgorithm tSignatureAlgorithm = SignatureAlgorithm.ED25519;

			return sign0(tPrivateKey, tPublicKey, tSignatureAlgorithm, someDataToSign);
		}

		throw new SshSignatureException("Mööp");
	}

	private SigningResult sign0(PrivateKey aPrivateKey, PublicKey aPublicKey, SignatureAlgorithm aSignatureAlgorithm,
			byte[] someDataToSign) throws SshSignatureException {

		SigningResult tSigningResult = new SigningResult();
		tSigningResult.publicKey = aPublicKey;
		tSigningResult.signatureAlgorithm = aSignatureAlgorithm;
		tSigningResult.signedContent = sign0(aPrivateKey, aSignatureAlgorithm, someDataToSign);
		return tSigningResult;
	}

	private byte[] sign0(PrivateKey aPrivateKey, SignatureAlgorithm aSignatureAlgorithm, byte[] someBytes)
			throws SshSignatureException {

		try {
			Signature tSignature = Signature.getInstance(aSignatureAlgorithm.getSignatureName());
			tSignature.initSign(aPrivateKey);
			tSignature.update(someBytes);
			byte[] tempSignedData = tSignature.sign();

			// System.out.println(tempSignedData.length);

			return tempSignedData;
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException exc) {
			throw new SshSignatureException("Actual signing failed!", exc);
		}
	}

	private SigningResult sign1(PrivateKey aPrivateKey, PublicKey aPublicKey, SignatureAlgorithm aSignatureAlgorithm,
			byte[] someDataToSign) throws SshSignatureException {

		byte[] tSigned = sign0(aPrivateKey, aSignatureAlgorithm, someDataToSign);
		// System.out.println(tSigned.length);
		// System.out.println(HexUtil.bytesToHex(tSigned));

		byte[] tResult = new byte[40];
		System.arraycopy(tSigned, 4, tResult, 0, 20);
		// System.out.println(HexUtil.bytesToHex(tResult));

		System.arraycopy(tSigned, 26, tResult, 20, 20);
		// System.out.println(HexUtil.bytesToHex(tResult));

		SigningResult tSigningResult = new SigningResult();
		tSigningResult.publicKey = aPublicKey;
		tSigningResult.signatureAlgorithm = aSignatureAlgorithm;
		tSigningResult.signedContent = tResult;
		return tSigningResult;
	}
}
