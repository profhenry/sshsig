//
// SigningEngine.java
//
// Copyright (C) 2023
// GEBIT Solutions GmbH
// Berlin, Dusseldorf, Leipzig, Lisbon, Stuttgart (Germany)
// All rights reserved.
//
package de.profhenry.sshsig.core.engine;

/**
 * @author profhenry
 */
public interface SigningEngine {

	public class SigningResult {

		public byte[] publicKey;

		public String signatureAlgorithm;

		public byte[] signedContent;
	}

	SigningResult sign(byte[] someDataToSign) throws Exception;

}
