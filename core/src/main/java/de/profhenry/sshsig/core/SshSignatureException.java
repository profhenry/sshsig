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
 * Signals that an error has occured when generating a SSH signature.
 * <p>
 * 
 * @author profhenry
 */
public class SshSignatureException extends Exception {

	/**
	 * Constructs a {@code SshSignatureException} with the specified message.
	 * <p>
	 * 
	 * @param aMessage the exception message
	 */
	public SshSignatureException(String aMessage) {
		super(aMessage);
	}

	/**
	 * Constructs a {@code SshSignatureException} with the specified message and cause.
	 * 
	 * @param aMessage the exception message
	 * @param aCause the exception which caused the error
	 */
	public SshSignatureException(String aMessage, Throwable aCause) {
		super(aMessage, aCause);
	}
}
