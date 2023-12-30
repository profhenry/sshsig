/* 
 * Copyright 2023 Jan Henrik Wiesner
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
	 * The default buffer size.
	 */
	private static final int DEFAULT_BUFFER_SIZE = 8192;

	/**
	 * The backend used for the actual singing.
	 * <p>
	 */
	private final SigningBackend<K> signingBackend;

	/**
	 * The encoder for public keys in the SSH format.
	 */
	private final SshPublicKeyEncoder publicKeyEncoder;

	/**
	 * The hash algorithm used for hashing the message.
	 */
	private final HashAlgorithm hashAlgorithm;

	/**
	 * The buffer size used when reading the message from an input stream.
	 */
	private final int bufferSize;

	private SshSignatureGenerator(SigningBackend<K> aSigningBackend, SshPublicKeyEncoder aPublicKeyEncoder,
			HashAlgorithm aHashAlgorithm, int aBufferSize) {
		signingBackend = aSigningBackend;
		publicKeyEncoder = aPublicKeyEncoder;
		hashAlgorithm = aHashAlgorithm;
		bufferSize = Math.max(1024, aBufferSize);
	}

	public SigningBackend<K> getSigningBackend() {
		return signingBackend;
	}

	public SshPublicKeyEncoder getPublicKeyEncoder() {
		return publicKeyEncoder;
	}

	public HashAlgorithm getHashAlgorithm() {
		return hashAlgorithm;
	}

	public int getBufferSize() {
		return bufferSize;
	}

	/**
	 * Generates a SSH signature for a string message.
	 * <p>
	 * 
	 * @param aKey the SSH key
	 * @param aNamespace the namespace
	 * @param aMessage the string message
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
	 * @param aKey the SSH key
	 * @param aNamespace the namespace
	 * @param aMessage the byte message
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
	 * @param aKey the SSH key
	 * @param aNamespace the namespace
	 * @param aFile the file
	 * @return the SSH signature
	 * @throws IOException in case reading from file failed
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
	 * @param aKey the key
	 * @param aNamespace the namespace
	 * @param anInputStream the inputstream
	 * @return the SSH signature
	 * @throws IOException in case reading from input stream failed
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

		byte[] tBuffer = new byte[bufferSize];
		int tReadBytes = 0;
		int i;
		while ((i = anInputStream.read(tBuffer, 0, tBuffer.length)) >= 0) {
			tMessageDigest.update(tBuffer, 0, i);
			tReadBytes += i;
		}

		byte[] tHash = tMessageDigest.digest();
		LOGGER.debug("hashed {} bytes using {} ({})",
				tReadBytes,
				tMessageDigest.getAlgorithm(),
				tMessageDigest.getProvider());
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
		LOGGER.debug("signed data: {}", HexUtil.bytesToHex(tSigningResult.getSignedContent()));

		SshBuffer tBuffer = new SshBuffer();
		tBuffer.appendPreamble(MAGIC_PREAMBLE);
		tBuffer.appendInt(SIG_VERSION);

		// public key
		tBuffer.appendByteArray(publicKeyEncoder.encodePublicKey(tSigningResult.getPublicKey()));
		// namespace
		tBuffer.appendString(aNamespace);
		// reserved
		tBuffer.appendInt(0);
		// hash algorithm
		tBuffer.appendString(hashAlgorithm.getNameUsedInSshProtocol());
		// signed content
		tBuffer.appendStringAndByteArray(tSigningResult.getSignatureAlgorithm().getNameUsedInSshProtocol(),
				tSigningResult.getSignedContent());

		return new SshSignature(tBuffer.toByteArray(), tSigningResult.getSignatureAlgorithm());
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
	 * @param aNamespace the namespace
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

	public static SshSignatureGenerator<KeyPair> create() {
		return new SshSignatureGenerator<>(new JcaSingingBackend(),
				new SshPublicKeyEncoder(),
				HashAlgorithm.SHA_512,
				DEFAULT_BUFFER_SIZE);
	}

	public <KK> SshSignatureGenerator<KK> withSigningBackend(SigningBackend<KK> aSigningBackend) {
		return new SshSignatureGenerator<>(aSigningBackend, publicKeyEncoder, hashAlgorithm, bufferSize);
	}

	public SshSignatureGenerator<K> withPublicKeyEncoder(SshPublicKeyEncoder aPublicKeyEncoder) {
		return new SshSignatureGenerator<>(signingBackend, aPublicKeyEncoder, hashAlgorithm, bufferSize);
	}

	public SshSignatureGenerator<K> withHashAlgorithm(HashAlgorithm aHashAlgorithm) {
		return new SshSignatureGenerator<>(signingBackend, publicKeyEncoder, aHashAlgorithm, bufferSize);
	}

	public SshSignatureGenerator<K> withBufferSize(int aBufferSize) {
		return new SshSignatureGenerator<>(signingBackend, publicKeyEncoder, hashAlgorithm, aBufferSize);
	}
}
