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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Defines the hash algorithms supported by SSH signature generation.
 * <p>
 * According to <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig">the SSH spec</a> the
 * following hash algorithms are supported
 * <ul>
 * <li>SHA-256</li>
 * <li>SHA-512 (default)</li>
 * </ul>
 * 
 * @author profhenry
 */
public enum HashAlgorithm {

	SHA_256("SHA-256", "sha256"),

	SHA_512("SHA-512", "sha512");

	/**
	 * Name for the corresponding JCA message digest.
	 */
	private final String messageDigestName;

	/**
	 * Name used in the SSH wire protocol.
	 */
	private final String nameUsedInSshProtocol;

	private HashAlgorithm(String aMessageDigestName, String aNameUsedInSshProtocol) {
		messageDigestName = aMessageDigestName;
		nameUsedInSshProtocol = aNameUsedInSshProtocol;
	}

	public MessageDigest createMessageDigestInstance() throws SshSignatureException {
		try {
			return MessageDigest.getInstance(messageDigestName);
		} catch (NoSuchAlgorithmException exc) {
			throw new SshSignatureException("Hash algorithm " + this + " not available!", exc);
		}
	}

	public String getNameUsedInSshProtocol() {
		return nameUsedInSshProtocol;
	}
}
