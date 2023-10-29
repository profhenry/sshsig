//
// SshKeyUtil.java
//
// Copyright (C) 2023
// GEBIT Solutions GmbH
// Berlin, Dusseldorf, Leipzig, Lisbon, Stuttgart (Germany)
// All rights reserved.
//
package de.profhenry.sshsig.core;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author profhenry
 */
public class SshKeyUtil {

	public static RSAPrivateKey readRsaPrivateKey(File aFile)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

		KeyFactory tKeyFactory = KeyFactory.getInstance("RSA");
		EncodedKeySpec tKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		RSAPrivateKey tPrivateKey = (RSAPrivateKey) tKeyFactory.generatePrivate(tKeySpec);

		return tPrivateKey;
	}

	public static RSAPublicKey readRsaPublicKey(File aFile)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

		KeyFactory tKeyFactory = KeyFactory.getInstance("RSA");
		EncodedKeySpec tKeySpec = new X509EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		RSAPublicKey tPublicKey = (RSAPublicKey) tKeyFactory.generatePublic(tKeySpec);

		return tPublicKey;
	}

	public static EdECPublicKey readEd25519PublicKey(File aFile)
			throws InvalidKeySpecException, NoSuchAlgorithmException, FileNotFoundException, IOException {

		KeyFactory tKeyFactory = KeyFactory.getInstance("Ed25519");
		EncodedKeySpec tKeySpec = new X509EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		EdECPublicKey tPublicKey = (EdECPublicKey) tKeyFactory.generatePublic(tKeySpec);

		return tPublicKey;
	}

	public static EdECPrivateKey readEd25519PrivateKey(File aFile)
			throws InvalidKeySpecException, NoSuchAlgorithmException, FileNotFoundException, IOException {

		KeyFactory tKeyFactory = KeyFactory.getInstance("Ed25519");
		EncodedKeySpec tKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		EdECPrivateKey tPublicKey = (EdECPrivateKey) tKeyFactory.generatePrivate(tKeySpec);

		return tPublicKey;
	}
}
