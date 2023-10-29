package de.profhenry.sshsig.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import de.profhenry.sshsig.core.engine.SigningEngine;
import de.profhenry.sshsig.core.engine.SigningEngine.SigningResult;

/**
 * @author profhenry
 */
public class SshSignatureGenerator {

	private static final String MAGIC_PREAMBLE = "SSHSIG";

	private static final int SIG_VERSION = 1;

	private final HashAlgorithm hashAlgorithm;

	private final SigningEngine signingEngine;

	private SshSignatureGenerator(SigningEngine aSigningEngine, HashAlgorithm aHashAlgorithm) {
		signingEngine = aSigningEngine;
		hashAlgorithm = aHashAlgorithm;
	}

	public HashAlgorithm getHashAlgorithm() {
		return hashAlgorithm;
	}

	public SigningEngine getSigningEngine() {
		return signingEngine;
	}

	public SshSignature generateSignature(String aNamespace, String aMessage) throws Exception {

		return generateSignature(aNamespace, aMessage.getBytes());
	}

	public SshSignature generateSignature(String aNamespace, File aFile) throws Exception {

		try (FileInputStream tFileInputStream = new FileInputStream(aFile)) {
			return generateSignature(aNamespace, tFileInputStream);
		}
	}

	public SshSignature generateSignature(String aNamespace, byte[] aMessage) throws Exception {

		return generateSignature(aNamespace, new ByteArrayInputStream(aMessage));
	}

	public SshSignature generateSignature(String aNamespace, InputStream aMessageInputStream) throws Exception {

		// call signature engine
		byte[] tDataToSign = test(aNamespace, hashAlgorithm, aMessageInputStream);
		SigningResult tSigningResult = signingEngine.sign(tDataToSign);

		ByteArrayOutputStream tOut = new ByteArrayOutputStream();
		DataOutputStream tDataStream = new DataOutputStream(tOut);
		tDataStream.writeBytes(MAGIC_PREAMBLE);
		tDataStream.writeInt(SIG_VERSION);

		// public key
		tDataStream.writeInt(tSigningResult.publicKey.length);
		tDataStream.write(tSigningResult.publicKey);
		// namespace
		tDataStream.writeInt(aNamespace.length());
		tDataStream.writeBytes(aNamespace);
		// reserved
		tDataStream.writeInt(0);
		// hash algotithm
		tDataStream.writeInt(hashAlgorithm.getNameUsedInSshProtocol().length());
		tDataStream.writeBytes(hashAlgorithm.getNameUsedInSshProtocol());

		// signed content
		tDataStream.writeInt(4 + tSigningResult.signatureAlgorithm.length() + 4 + tSigningResult.signedContent.length);
		tDataStream.writeInt(tSigningResult.signatureAlgorithm.length());
		tDataStream.writeBytes(tSigningResult.signatureAlgorithm);
		tDataStream.writeInt(tSigningResult.signedContent.length);
		tDataStream.write(tSigningResult.signedContent);

		tDataStream.flush();
		return new SshSignature(tOut.toByteArray(), tSigningResult.signatureAlgorithm);
	}

	private byte[] hash(InputStream aMessageInputStream, HashAlgorithm aHashAlgorithm)
			throws NoSuchAlgorithmException, IOException {

		MessageDigest tMessageDigest = MessageDigest.getInstance(aHashAlgorithm.getMessageDigestName());
		DigestOutputStream tDigestOutputStream =
				new DigestOutputStream(OutputStream.nullOutputStream(), tMessageDigest);
		aMessageInputStream.transferTo(tDigestOutputStream);
		return tMessageDigest.digest();
	}

	private byte[] test(String aNamespace, HashAlgorithm aHashAlgorithm, InputStream aMessageInputStream)
			throws NoSuchAlgorithmException, IOException {

		byte[] tHashedMessage = hash(aMessageInputStream, aHashAlgorithm);

		System.out.println("message: " + HexFormat.of().formatHex(tHashedMessage));

		ByteArrayOutputStream tOut = new ByteArrayOutputStream();
		DataOutputStream tDataStream = new DataOutputStream(tOut);
		tDataStream.writeBytes(MAGIC_PREAMBLE);
		tDataStream.writeInt(aNamespace.length());
		tDataStream.writeBytes(aNamespace);
		tDataStream.writeInt(0);
		tDataStream.writeInt(aHashAlgorithm.getNameUsedInSshProtocol().length());
		tDataStream.writeBytes(aHashAlgorithm.getNameUsedInSshProtocol());
		tDataStream.writeInt(tHashedMessage.length);
		tDataStream.write(tHashedMessage);

		tDataStream.flush();
		return tOut.toByteArray();
	}

	public static SshSignatureGenerator create(SigningEngine aSigningEngine) {
		return new SshSignatureGenerator(aSigningEngine, HashAlgorithm.SHA_512);
	}

	public SshSignatureGenerator withHashAlgorithm(HashAlgorithm aHashAlgorithm) {
		return new SshSignatureGenerator(signingEngine, aHashAlgorithm);
	}

}
