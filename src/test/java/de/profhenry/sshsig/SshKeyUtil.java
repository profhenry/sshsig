//
// SshKeyUtil.java
//
// Copyright (C) 2023
// GEBIT Solutions GmbH
// Berlin, Dusseldorf, Leipzig, Lisbon, Stuttgart (Germany)
// All rights reserved.
//
package de.profhenry.sshsig;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * @author jwiesner
 */
public class SshKeyUtil {

	public static RSAPrivateKey readPrivateKey(File aFile)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		KeyFactory tKeyFactory = KeyFactory.getInstance("RSA");

		try (FileReader tFileReader = new FileReader(aFile); PemReader tPemReader = new PemReader(tFileReader)) {
			PemObject tPemObject = tPemReader.readPemObject();
			EncodedKeySpec tKeySpec = new PKCS8EncodedKeySpec(tPemObject.getContent());
			RSAPrivateKey tPrivateKey = (RSAPrivateKey) tKeyFactory.generatePrivate(tKeySpec);

			return tPrivateKey;
		}
	}

	public static RSAPublicKey readPublicKey(File aFile)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		KeyFactory tKeyFactory = KeyFactory.getInstance("RSA");

		try (FileReader tFileReader = new FileReader(aFile); PemReader tPemReader = new PemReader(tFileReader)) {
			PemObject tPemObject = tPemReader.readPemObject();
			EncodedKeySpec tKeySpec = new X509EncodedKeySpec(tPemObject.getContent());
			RSAPublicKey tPublicKey = (RSAPublicKey) tKeyFactory.generatePublic(tKeySpec);

			return tPublicKey;
		}
	}
}
