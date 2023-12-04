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
 * @author profhenry
 * @param <K> the type for
 */
public interface SigningBackend<K> {

	static class SigningResult {

		private SignatureAlgorithm signatureAlgorithm;

		private byte[] signedContent;

		private PublicKey publicKey;

		public SigningResult(SignatureAlgorithm aSignatureAlgorithm, byte[] aSignedContent, PublicKey aPublicKey) {
			signatureAlgorithm = aSignatureAlgorithm;
			signedContent = aSignedContent;
			publicKey = aPublicKey;
		}

		public SignatureAlgorithm getSignatureAlgorithm() {
			return signatureAlgorithm;
		}

		public byte[] getSignedContent() {
			return signedContent;
		}

		public PublicKey getPublicKey() {
			return publicKey;
		}

	}

	SigningResult signData(K aKey, byte[] someDataToSign) throws SshSignatureException;
}
