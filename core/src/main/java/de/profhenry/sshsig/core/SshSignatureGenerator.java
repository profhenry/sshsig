package de.profhenry.sshsig.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.profhenry.sshsig.core.spi.SigningBackend;
import de.profhenry.sshsig.core.spi.SigningBackend.SigningResult;
import de.profhenry.sshsig.core.util.HexUtil;

/**
 * fdsfs for singing data using a SSH key
 * <p>
 * https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig data since
 * <p>
 * OpenSSH 8.1
 * 
 * @author profhenry
 * @param <K> sdsds
 */
public final class SshSignatureGenerator<K> {

	/**
	 * The logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(SshSignatureGenerator.class);

	/**
	 * The preamble of the signature blob according to the SSH spec.
	 */
	private static final String MAGIC_PREAMBLE = "SSHSIG";

	/**
	 * The version of the signature blob according to the SSH spec.
	 */
	private static final int SIG_VERSION = 1;

	/**
	 * The buffer size used when reading the message from an input stream.
	 */
	private static final int BUFFER_SIZE = 8192;

	/**
	 * The backend used for the actual singing.
	 * <p>
	 */
	private final SigningBackend<K> signingBackend;

	private final PublicKeyEncoder publicKeyEncoder;

	/**
	 * The hash algorithm used for hashing the message.
	 */
	private final HashAlgorithm hashAlgorithm;

	private SshSignatureGenerator(SigningBackend<K> aSigningBackend, PublicKeyEncoder aPublicKeyEncoder,
			HashAlgorithm aHashAlgorithm) {
		signingBackend = aSigningBackend;
		publicKeyEncoder = aPublicKeyEncoder;
		hashAlgorithm = aHashAlgorithm;
	}

	public SigningBackend<K> getSigningBackend() {
		return signingBackend;
	}

	public HashAlgorithm getHashAlgorithm() {
		return hashAlgorithm;
	}

	/**
	 * Generates a SSH signature for a string message.
	 * <p>
	 * 
	 * @param aKey       the SSH key
	 * @param aNamespace the namespace
	 * @param aMessage   the string message
	 * @return the SSH signature
	 * @throws SshSignatureException in case signature generation failed
	 */
	public SshSignature generateSignature(K aKey, String aNamespace, String aMessage) throws SshSignatureException {
		Objects.requireNonNull(aKey, "key is required.");
		Objects.requireNonNull(aNamespace, "namespace is required.");
		Objects.requireNonNull(aMessage, "message is required.");

		LOGGER.info("Generating SSH signature...");
		LOGGER.info("namespace: '{}'", aNamespace);
		LOGGER.info("message: '{}'", aMessage);

		return generateSignature0(aKey, aNamespace, hashMessage(aMessage.getBytes()));
	}

	/**
	 * Generates a SSH signature for a byte message.
	 * <p>
	 * 
	 * @param aKey       the SSH key
	 * @param aNamespace the namespace
	 * @param aMessage   the byte message
	 * @return the SSH signature
	 * @throws SshSignatureException in case signature generation failed
	 */
	public SshSignature generateSignature(K aKey, String aNamespace, byte[] aMessage) throws SshSignatureException {
		Objects.requireNonNull(aKey, "key is required.");
		Objects.requireNonNull(aNamespace, "namespace is required.");
		Objects.requireNonNull(aMessage, "message is required.");

		LOGGER.info("Generating SSH signature...");
		LOGGER.info("namespace: '{}'", aNamespace);
		LOGGER.info("message: {}", Arrays.toString(aMessage));

		return generateSignature0(aKey, aNamespace, hashMessage(aMessage));
	}

	/**
	 * Generates a SSH signature for the content of a file.
	 * <p>
	 * 
	 * @param aKey       the SSH key
	 * @param aNamespace the namespace
	 * @param aFile      the file
	 * @return the SSH signature
	 * @throws IOException           in case reading from file failed
	 * @throws SshSignatureException in case signature generation failed
	 */
	public SshSignature generateSignature(K aKey, String aNamespace, File aFile)
			throws IOException, SshSignatureException {
		Objects.requireNonNull(aKey, "key is required.");
		Objects.requireNonNull(aNamespace, "namespace is required.");
		Objects.requireNonNull(aFile, "file is required.");

		LOGGER.info("Generating SSH signature...");
		LOGGER.info("namespace: '{}'", aNamespace);
		LOGGER.info("message: {}", aFile.getCanonicalPath());

		try (FileInputStream tFileInputStream = new FileInputStream(aFile)) {
			return generateSignature0(aKey, aNamespace, hashMessage(tFileInputStream));
		}
	}

	/**
	 * Generates a SSH signature for data provided by an input stream.
	 * <p>
	 * 
	 * @param aKey          the key
	 * @param aNamespace    the namespace
	 * @param anInputStream the inputstream
	 * @return the SSH signature
	 * @throws IOException           in case reading from input stream failed
	 * @throws SshSignatureException in case signature generation failed
	 */
	public SshSignature generateSignature(K aKey, String aNamespace, InputStream anInputStream)
			throws IOException, SshSignatureException {
		Objects.requireNonNull(aKey, "key is required.");
		Objects.requireNonNull(aNamespace, "namespace is required.");
		Objects.requireNonNull(anInputStream, "input stream is required.");

		LOGGER.info("Generating SSH signature...");
		LOGGER.info("namespace: '{}'", aNamespace);
		LOGGER.info("message: {}", anInputStream.getClass().getName());

		return generateSignature0(aKey, aNamespace, hashMessage(anInputStream));
	}

	private byte[] hashMessage(byte[] aMessage) throws SshSignatureException {
		MessageDigest tMessageDigest = hashAlgorithm.createMessageDigestInstance();

		LOGGER.debug("hashed {} bytes using {} ({})",
				aMessage.length,
				tMessageDigest.getAlgorithm(),
				tMessageDigest.getProvider());
		byte[] tHash = tMessageDigest.digest(aMessage);
		LOGGER.debug("hashed message: {}", HexUtil.bytesToHex(tHash));
		return tHash;
	}

	private byte[] hashMessage(InputStream anInputStream) throws SshSignatureException, IOException {
		MessageDigest tMessageDigest = hashAlgorithm.createMessageDigestInstance();

		byte[] tBuffer = new byte[BUFFER_SIZE];
		int tReadBytes = 0;
		int i;
		while ((i = anInputStream.read(tBuffer, 0, tBuffer.length)) >= 0) {
			tMessageDigest.update(tBuffer, 0, i);
			tReadBytes += i;
		}

		LOGGER.debug("hashed {} bytes using {} ({})",
				tReadBytes,
				tMessageDigest.getAlgorithm(),
				tMessageDigest.getProvider());
		byte[] tHash = tMessageDigest.digest();
		LOGGER.debug("hashed message: {}", HexUtil.bytesToHex(tHash));
		return tHash;
	}

	private SshSignature generateSignature0(K aKey, String aNamespace, byte[] aHashedMessage)
			throws SshSignatureException {

		// 1) generate the data to sign
		byte[] tDataToSign = generateDataToSign(aNamespace, aHashedMessage);
		LOGGER.debug("data to sign: {}", HexUtil.bytesToHex(tDataToSign));

		// call signature engine
		SigningResult tSigningResult = signingBackend.signData(aKey, tDataToSign);
		LOGGER.debug("signed data: {}", HexUtil.bytesToHex(tSigningResult.signedContent));

		SshBuffer tBuffer = new SshBuffer();
		tBuffer.appendPreamble(MAGIC_PREAMBLE);
		tBuffer.appendInt(SIG_VERSION);

		// public key
		tBuffer.appendByteArray(publicKeyEncoder.encodePublicKey(tSigningResult.publicKey));
		// namespace
		tBuffer.appendString(aNamespace);
		// reserved
		tBuffer.appendInt(0);
		// hash algorithm
		tBuffer.appendString(hashAlgorithm.getNameUsedInSshProtocol());
		// signed content
		tBuffer.appendStringAndByteArray(tSigningResult.signatureAlgorithm.getNameUsedInSshProtocol(),
				tSigningResult.signedContent);

		return new SshSignature(tBuffer.toByteArray(), tSigningResult.signatureAlgorithm);
	}

	/**
	 * Generates the blob containing the data which gets actually signed.
	 * <p>
	 * The blob contains the following data (as specified <a href=
	 * "https://github.com/openssh/openssh-portable/blob/c8ed7cc545879ac15f6ce428be4b29c35598bb2a/PROTOCOL.sshsig#L79">here</a>):
	 * <ol>
	 * <li>the {@link SshSignatureGenerator#MAGIC_PREAMBLE MAGIC_PREAMBLE}
	 * <li>the namespace</li>
	 * <li>reserved for future use</li>
	 * <li>the hash algorithm</li>
	 * <li>the hashed message</li>
	 * </ol>
	 * <p>
	 * 
	 * @param aNamespace     the namespace
	 * @param aHashedMessage the hashed message
	 * @return the blob
	 */
	private byte[] generateDataToSign(String aNamespace, byte[] aHashedMessage) {
		SshBuffer tBuffer = new SshBuffer();
		tBuffer.appendPreamble(MAGIC_PREAMBLE);
		tBuffer.appendString(aNamespace);
		tBuffer.appendInt(0); // reserved for future use
		tBuffer.appendString(hashAlgorithm.getNameUsedInSshProtocol());
		tBuffer.appendByteArray(aHashedMessage);
		return tBuffer.toByteArray();
	}

	// =================================================================================================================

	public static <K> SshSignatureGenerator<K> create(SigningBackend<K> aSigningEngine) {
		return new SshSignatureGenerator<>(aSigningEngine, new PublicKeyEncoder(), HashAlgorithm.SHA_512);
	}

	public static SshSignatureGenerator<KeyPair> create() {
		return new SshSignatureGenerator<>(new JcaSingingBackend(), new PublicKeyEncoder(), HashAlgorithm.SHA_512);
	}

	public SshSignatureGenerator<K> withHashAlgorithm(HashAlgorithm aHashAlgorithm) {
		return new SshSignatureGenerator<>(signingBackend, publicKeyEncoder, aHashAlgorithm);
	}
}
