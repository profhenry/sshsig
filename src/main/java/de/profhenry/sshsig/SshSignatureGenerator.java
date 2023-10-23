package de.profhenry.sshsig;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author profhenry
 */
public class SshSignatureGenerator {

	private static final String MAGIC_PREAMBLE = "SSHSIG";

	private static final int SIG_VERSION = 1;

	private final RSAPrivateKey privateKey;

	private final RSAPublicKey publicKey;

	private final HashAlgorithm hashAlgorithm;

	private final SignatureAlgorithm signatureAlgorithm;

	private SshSignatureGenerator(RSAPrivateKey aPrivateKey, RSAPublicKey aPublicKey, HashAlgorithm aHashAlgorithm,
			SignatureAlgorithm aSignatureAlgorithm) {
		privateKey = aPrivateKey;
		publicKey = aPublicKey;
		hashAlgorithm = aHashAlgorithm;
		signatureAlgorithm = aSignatureAlgorithm;
	}

	public HashAlgorithm getHashAlgorithm() {
		return hashAlgorithm;
	}

	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public SshSignature generateSignature(String aNamespace, String aMessage)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

		return generateSignature(aNamespace, aMessage.getBytes());
	}

	public SshSignature generateSignature(String aNamespace, File aFile) throws FileNotFoundException, IOException,
			InvalidKeyException, NoSuchAlgorithmException, SignatureException {

		try (FileInputStream tFileInputStream = new FileInputStream(aFile)) {
			return generateSignature(aNamespace, tFileInputStream);
		}
	}

	public SshSignature generateSignature(String aNamespace, byte[] aMessage)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

		return generateSignature(aNamespace, new ByteArrayInputStream(aMessage));
	}

	public SshSignature generateSignature(String aNamespace, InputStream aMessageInputStream)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		ByteArrayOutputStream tOut = new ByteArrayOutputStream();
		DataOutputStream tDataStream = new DataOutputStream(tOut);
		tDataStream.writeBytes(MAGIC_PREAMBLE);
		tDataStream.writeInt(SIG_VERSION);

		// public key
		tDataStream.writeInt(4 + 7 + 4 + publicKey.getPublicExponent().toByteArray().length + 4
				+ publicKey.getModulus().toByteArray().length);
		tDataStream.writeInt(7);
		tDataStream.writeBytes("ssh-rsa");
		tDataStream.writeInt(publicKey.getPublicExponent().toByteArray().length);
		tDataStream.write(publicKey.getPublicExponent().toByteArray());
		tDataStream.writeInt(publicKey.getModulus().toByteArray().length);
		tDataStream.write(publicKey.getModulus().toByteArray());
		// namespace
		tDataStream.writeInt(aNamespace.length());
		tDataStream.writeBytes(aNamespace);
		// reserved
		tDataStream.writeInt(0);
		// hash algotithm
		tDataStream.writeInt(hashAlgorithm.getNameUsedInSshProtocol().length());
		tDataStream.writeBytes(hashAlgorithm.getNameUsedInSshProtocol());

		// signature
		byte[] tDataToSign = test(aNamespace, hashAlgorithm, aMessageInputStream);
		byte[] tempSigned = sign(signatureAlgorithm, tDataToSign);
		tDataStream.writeInt(4 + signatureAlgorithm.getNameUsedInSshProtocol().length() + 4 + tempSigned.length);
		tDataStream.writeInt(signatureAlgorithm.getNameUsedInSshProtocol().length());
		tDataStream.writeBytes(signatureAlgorithm.getNameUsedInSshProtocol());
		tDataStream.writeInt(tempSigned.length);
		tDataStream.write(tempSigned);

		tDataStream.flush();

		return new SshSignature(tOut.toByteArray());
	}

	private byte[] sign(SignatureAlgorithm aSignatureAlgorithm, byte[] someBytes)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature tSignature = Signature.getInstance(aSignatureAlgorithm.getSignatureName());
		tSignature.initSign(privateKey);
		tSignature.update(someBytes);
		byte[] tempSignedData = tSignature.sign();

		return tempSignedData;
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

	public SshSignatureGenerator with(HashAlgorithm aHashAlgorithm) {
		return new SshSignatureGenerator(privateKey, publicKey, aHashAlgorithm, signatureAlgorithm);
	}

	public SshSignatureGenerator with(SignatureAlgorithm aSignatureAlgorithm) {
		return new SshSignatureGenerator(privateKey, publicKey, hashAlgorithm, aSignatureAlgorithm);
	}

	public static SshSignatureGenerator create(RSAPrivateKey aPrivateKey, RSAPublicKey aPublicKey) {
		return new SshSignatureGenerator(aPrivateKey,
				aPublicKey,
				HashAlgorithm.SHA_512,
				SignatureAlgorithm.RSA_SHA2_512);
	}
}
