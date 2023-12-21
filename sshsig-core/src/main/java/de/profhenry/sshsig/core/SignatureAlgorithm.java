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

/**
 * Defines the signature algorithms which are used for SSH signatures.
 * <p>
 * 
 * @author profhenry
 */
public enum SignatureAlgorithm {

	SSH_DSS("ssh-dss"),

	RSA_SHA2_256("rsa-sha2-256"),

	RSA_SHA2_512("rsa-sha2-512"),

	SSH_ED25519("ssh-ed25519");

	/**
	 * Name used in the SSH wire protocol.
	 */
	private final String nameUsedInSshProtocol;

	private SignatureAlgorithm(String aNameUsedInSshProtocol) {
		nameUsedInSshProtocol = aNameUsedInSshProtocol;
	}

	public String getNameUsedInSshProtocol() {
		return nameUsedInSshProtocol;
	}
}
