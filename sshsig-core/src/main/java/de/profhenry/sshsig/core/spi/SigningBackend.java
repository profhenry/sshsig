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
package de.profhenry.sshsig.core.spi;

import java.security.PublicKey;

import de.profhenry.sshsig.core.SignatureAlgorithm;
import de.profhenry.sshsig.core.SshSignatureException;

/**
 * SPI for signing backends.
 * <p>
 * The singing backend is responsible for the actual signing. The signing can be done by this class itself or might be
 * delegated to some external process (like when using an SSH agent). Depending on this the passed key information might
 * look different. In the first case the key information must contain the private key in the second case the public key
 * (or even just some kind of identifier) might be sufficient.
 * <p>
 * 
 * @author profhenry
 * @param <K> the type for the key information
 */
public interface SigningBackend<K> {

	/**
	 * Data container for a signing result.
	 * <p>
	 * 
	 * @author profhenry
	 */
	class SigningResult {

		/**
		 * The used signature algorithm.
		 */
		private SignatureAlgorithm signatureAlgorithm;

		/**
		 * The signed content.
		 */
		private byte[] signedContent;

		public SigningResult(SignatureAlgorithm aSignatureAlgorithm, byte[] someSignedContent) {
			signatureAlgorithm = aSignatureAlgorithm;
			signedContent = someSignedContent;
		}

		public SignatureAlgorithm getSignatureAlgorithm() {
			return signatureAlgorithm;
		}

		public byte[] getSignedContent() {
			return signedContent;
		}
	}

	/**
	 * Method for extracting the public key from the key information.
	 * <p>
	 * This is required because the public key gets encoded in the SSH signature.
	 * <p>
	 * 
	 * @param someKeyInformation the key information
	 * @return the public key
	 */
	PublicKey extractPublicKey(K someKeyInformation);

	/**
	 * Method for signing data using the provided key information.
	 * <p>
	 * 
	 * @param someKeyInformation the key information
	 * @param someDataToSign the blob to be signed
	 * @return the signing result
	 * @throws SshSignatureException in case the signing failed
	 */
	SigningResult signData(K someKeyInformation, byte[] someDataToSign) throws SshSignatureException;
}
