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
package de.profhenry.sshsig.mina;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.sshd.agent.SshAgent;

import de.profhenry.sshsig.core.SignatureAlgorithm;
import de.profhenry.sshsig.core.SshSignatureException;
import de.profhenry.sshsig.core.spi.SigningBackend;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

/**
 * @author profhenry
 */
public class ApacheMinaSshAgentEngine implements SigningBackend<PublicKey> {

	private final SshAgent sshAgent;

	public ApacheMinaSshAgentEngine(SshAgent anSshAgent) {
		sshAgent = anSshAgent;
	}

	@Override
	public SigningResult signData(PublicKey aPublicKey, byte[] someDataToSign) throws SshSignatureException {
		// 1) determine signature algorithm
		SignatureAlgorithm tSignatureAlgorithm = determineSignatureAlgorithm(aPublicKey);

		byte[] tSignedContent;

		try {
			tSignedContent =
					sshAgent.sign(null, aPublicKey, tSignatureAlgorithm.getNameUsedInSshProtocol(), someDataToSign)
							.getValue();
		} catch (IOException exc) {
			throw new SshSignatureException("", exc);
		}

		return new SigningResult(tSignatureAlgorithm, tSignedContent, aPublicKey);
	}

	protected SignatureAlgorithm determineSignatureAlgorithm(PublicKey aPublicKey) throws SshSignatureException {
		if (aPublicKey instanceof DSAPublicKey) {
			return SignatureAlgorithm.SSH_DSS;
		}
		if (aPublicKey instanceof RSAPublicKey) {
			// TODO RSA_SHA2_256 would also be an option here
			return SignatureAlgorithm.RSA_SHA2_512;
		}
		if (aPublicKey instanceof EdDSAPublicKey) {
			return SignatureAlgorithm.SSH_ED25519;
		}
		throw new SshSignatureException(
				"Unsupported public key: " + aPublicKey.getAlgorithm() + " (" + aPublicKey.getClass().getName() + ")");
	}
}
