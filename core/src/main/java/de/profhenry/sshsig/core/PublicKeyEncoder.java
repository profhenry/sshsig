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

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author profhenry
 */
public class PublicKeyEncoder {

	private static final String KEY_FORMAT_IDENTIFIER_DSS = "ssh-dss";

	private static final String KEY_FORMAT_IDENTIFIER_RSA = "ssh-rsa";

	private static final String KEY_FORMAT_IDENTIFIER_ED25519 = "ssh-ed25519";

	public byte[] encodePublicKey(PublicKey aPublicKey) throws SshSignatureException {
		if (aPublicKey instanceof DSAPublicKey) {
			return encodeDsaPublicKey((DSAPublicKey) aPublicKey);
		}
		if (aPublicKey instanceof RSAPublicKey) {
			return encodeRsaPublicKey((RSAPublicKey) aPublicKey);
		}
		if ("EdDSA".equals(aPublicKey.getAlgorithm())) {
			// used by JDK17 and net.i2p.crypto
			return encodeEd25519PublicKey(aPublicKey);
		}
		if ("Ed25519".equals(aPublicKey.getAlgorithm())) {
			// used by org.bouncycastle
			return encodeEd25519PublicKey(aPublicKey);
		}
		throw new SshSignatureException("Could not encode public key (" + aPublicKey.getClass().getName() + ")!");
	}

	/**
	 * Encodes a DSA public key.
	 * <p>
	 * According to <a href="https://www.rfc-editor.org/rfc/rfc4253#page-14">RTC 4253</a> DSA public key encoding is
	 * <ul>
	 * <li>the key format identifier (ssh-dss)</li>
	 * <li>prime (p)</li>
	 * <li>subprime (q)</li>
	 * <li>base (g)</li>
	 * <li>public key (y)</li>
	 * </ul>
	 * 
	 * @param aDsaPublicKey the DSA public key
	 * @return the encoded DSA public key
	 */
	protected final byte[] encodeDsaPublicKey(DSAPublicKey aDsaPublicKey) {
		SshBuffer tBuffer = new SshBuffer();
		tBuffer.appendString(KEY_FORMAT_IDENTIFIER_DSS);
		tBuffer.appendBigInteger(aDsaPublicKey.getParams().getP());
		tBuffer.appendBigInteger(aDsaPublicKey.getParams().getQ());
		tBuffer.appendBigInteger(aDsaPublicKey.getParams().getG());
		tBuffer.appendBigInteger(aDsaPublicKey.getY());
		return tBuffer.toByteArray();
	}

	/**
	 * Encodes a RSA public key.
	 * <p>
	 * According to <a href="https://www.rfc-editor.org/rfc/rfc4253#page-15">RTC 4253</a> RSA public key encoding is
	 * <ul>
	 * <li>the key format identifier (ssh-rsa)</li>
	 * <li>RSA public exponent (e)</li>
	 * <li>RSA modulus (n)</li>
	 * </ul>
	 * 
	 * @param aRsaPublicKey the RSA public key
	 * @return the encoded RSA public key
	 */
	protected final byte[] encodeRsaPublicKey(RSAPublicKey aRsaPublicKey) {
		SshBuffer tBuffer = new SshBuffer();
		tBuffer.appendString(KEY_FORMAT_IDENTIFIER_RSA);
		tBuffer.appendBigInteger(aRsaPublicKey.getPublicExponent());
		tBuffer.appendBigInteger(aRsaPublicKey.getModulus());
		return tBuffer.toByteArray();
	}

	/**
	 * Encodes a ED25519 public key.
	 * <p>
	 * According to <a href="https://tools.ietf.org/html/rfc8709">RFC 8709</a> ED25519 public key encoding is
	 * <ul>
	 * <li>the key format identifier (ssh-ed25519)</li>
	 * <li>the public key (A)</li>
	 * </ul>
	 * <p>
	 * <b>NOTE:</b><br>
	 * Since we are compiling against a JDK8 which has no support for ED25519 we are not able to provide a proper
	 * encoding method :-/. For the case the public key has the X.509 format we can extract the 32 bytes from the X.509
	 * encoding.
	 * 
	 * @param aPublicKey the ED25519 public key
	 * @return the encoded ED25519 key
	 * @throws SshSignatureException in case key is not in X.509 format
	 */
	protected byte[] encodeEd25519PublicKey(PublicKey aPublicKey) throws SshSignatureException {
		if ("X.509".equals(aPublicKey.getFormat())) {
			SshBuffer tBuffer = new SshBuffer();
			tBuffer.appendString(KEY_FORMAT_IDENTIFIER_ED25519);
			// In X.509 format a ED25519 public key is ASN.1 encoded
			// (https://tools.ietf.org/html/draft-ietf-curdle-pkix-04).
			// The encoding has always 44 bytes and the actual public key are always the last 32 bytes
			tBuffer.appendByteArray(aPublicKey.getEncoded(), 12, 32);
			return tBuffer.toByteArray();
		}
		throw new SshSignatureException(
				"Cannot encode ED25519 public key which has " + aPublicKey.getFormat() + " format!");
	}
}
