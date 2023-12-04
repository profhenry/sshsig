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
import de.profhenry.sshsig.core.util.HexUtil;

/**
 * A {@link SigningBackend} using the Java Cryptography Architecture (JCA).
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
			throw new SshSignatureException("Key mismatch detected: private="
					+ tPrivateKey.getAlgorithm()
					+ " public="
					+ tPublicKey.getAlgorithm());
		}

		if ("DSA".equals(tPrivateKey.getAlgorithm())) {
			return signDsa(tPrivateKey, tPublicKey, someDataToSign);
		}
		if ("RSA".equals(tPrivateKey.getAlgorithm())) {
			return signRsa(tPrivateKey, tPublicKey, someDataToSign);
		}
		if ("EdDSA".equals(tPrivateKey.getAlgorithm())) {
			// used by JDK17 and net.i2p.crypto
			// JDK17 uses EdDSA for Ed25519 and Ed448
			// TODO i would love to prevent Ed448 but i think this is not possible when compiling againt JDK8 :-/
			return signEd25519(tPrivateKey, tPublicKey, someDataToSign);
		}
		if ("Ed25519".equals(tPrivateKey.getAlgorithm())) {
			// used by org.bouncycastle
			return signEd25519(tPrivateKey, tPublicKey, someDataToSign);
		}

		throw new SshSignatureException("Unsupported private key: "
				+ tPrivateKey.getAlgorithm()
				+ " ("
				+ tPrivateKey.getClass().getName()
				+ ")");
	}

	private byte[] sign(PrivateKey aPrivateKey, String anAlgorithm, byte[] someDataToSign)
			throws SshSignatureException {

		try {
			Signature tSignature = Signature.getInstance(anAlgorithm);
			tSignature.initSign(aPrivateKey);
			tSignature.update(someDataToSign);
			return tSignature.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException exc) {
			throw new SshSignatureException("Signing failed!", exc);
		}
	}

	private SigningResult signDsa(PrivateKey aPrivateKey, PublicKey aPublicKey, byte[] someDataToSign)
			throws SshSignatureException {

		byte[] tSignedData = sign(aPrivateKey, "SHA1WithDSA", someDataToSign);
		// DSA signatures consists of the two integers r and s.
		// The signature data returned by SHA1WithDSA is ASN.1 encoded.
		// But signature data for SSH DSS requires just the two integers (20 bytes each, big endian).

		LOGGER.debug("ASN.1 encoded dsa signed data ({} bytes) {}",
				tSignedData.length,
				HexUtil.bytesToHex(tSignedData));

		int tLengthR = tSignedData[3];
		int tOffsetR = 4;
		int tLengthS = tSignedData[tOffsetR + tLengthR + 1];
		int tOffsetS = tOffsetR + tLengthR + 2;

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("extracting r: offset={} length={}", tOffsetR, tLengthR);
			byte[] tR = new byte[tLengthR];
			System.arraycopy(tSignedData, tOffsetR, tR, 0, tLengthR);
			LOGGER.debug("r: {}", HexUtil.bytesToHex(tR));

			LOGGER.debug("extracting s: offset={} length={}", tOffsetS, tLengthS);
			byte[] tS = new byte[tLengthS];
			System.arraycopy(tSignedData, tOffsetS, tS, 0, tLengthS);
			LOGGER.debug("s: {}", HexUtil.bytesToHex(tS));
		}

		byte[] tRAndS = new byte[40];
		arrayCopyExact20Bytes(tSignedData, tOffsetR, tRAndS, 0, tLengthR);
		arrayCopyExact20Bytes(tSignedData, tOffsetS, tRAndS, 20, tLengthS);
		LOGGER.debug("r+s: {}", HexUtil.bytesToHex(tRAndS));
		LOGGER.debug("     <                  r                   ><                  s                   >");

		return new SigningResult(SignatureAlgorithm.SSH_DSS, tRAndS, aPublicKey);
	}

	private void arrayCopyExact20Bytes(byte[] aSrc, int aScrOffset, byte[] aDst, int aDstOffset, int aLength) {
		if (aLength <= 20) {
			System.arraycopy(aSrc, aScrOffset, aDst, aDstOffset + 20 - aLength, aLength);
		} else if (aLength == 21 && aSrc[aScrOffset] == 0) {
			System.arraycopy(aSrc, aScrOffset + 1, aDst, aDstOffset, 20);
		} else {
			throw new IllegalArgumentException();
		}
	}

	private SigningResult signRsa(PrivateKey aPrivateKey, PublicKey aPublicKey, byte[] someDataToSign)
			throws SshSignatureException {

		byte[] tSignedData = sign(aPrivateKey, "SHA512WithRSA", someDataToSign);
		return new SigningResult(SignatureAlgorithm.RSA_SHA2_512, tSignedData, aPublicKey);
	}

	private SigningResult signEd25519(PrivateKey aPrivateKey, PublicKey aPublicKey, byte[] someDataToSign)
			throws SshSignatureException {

		byte[] tSignedData;
		if ("net.i2p.crypto.eddsa.EdDSAPrivateKey".equals(aPrivateKey.getClass().getName())) {
			tSignedData = sign(aPrivateKey, "NONEwithEdDSA", someDataToSign);
		} else {
			tSignedData = sign(aPrivateKey, "ED25519", someDataToSign);
		}
		return new SigningResult(SignatureAlgorithm.SSH_ED25519, tSignedData, aPublicKey);
	}
}
