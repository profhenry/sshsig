package de.profhenry.sshsig.core;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author profhenry
 */
public class SshKeyUtil {

	public static DSAPrivateKey readDsaPrivateKey(File aFile) throws Exception {
		KeyFactory tKeyFactory = KeyFactory.getInstance("DSA");
		EncodedKeySpec tKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		DSAPrivateKey tPrivateKey = (DSAPrivateKey) tKeyFactory.generatePrivate(tKeySpec);
		return tPrivateKey;
	}

	public static DSAPublicKey readDsaPublicKey(File aFile) throws Exception {
		KeyFactory tKeyFactory = KeyFactory.getInstance("DSA");
		EncodedKeySpec tKeySpec = new X509EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		DSAPublicKey tPublicKey = (DSAPublicKey) tKeyFactory.generatePublic(tKeySpec);
		return tPublicKey;
	}

	public static KeyPair readDsaKeyPair() throws Exception {
		DSAPrivateKey tPrivateKey = readDsaPrivateKey(new File("../testkeys/test_dsa_pkcs8.der"));
		DSAPublicKey tPublicKey = readDsaPublicKey(new File("../testkeys/test_dsa.pub_x509.der"));
		return new KeyPair(tPublicKey, tPrivateKey);
	}

	public static RSAPrivateKey readRsaPrivateKey(File aFile) throws Exception {
		KeyFactory tKeyFactory = KeyFactory.getInstance("RSA");
		EncodedKeySpec tKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		RSAPrivateKey tPrivateKey = (RSAPrivateKey) tKeyFactory.generatePrivate(tKeySpec);
		return tPrivateKey;
	}

	public static RSAPublicKey readRsaPublicKey(File aFile) throws Exception {
		KeyFactory tKeyFactory = KeyFactory.getInstance("RSA");
		EncodedKeySpec tKeySpec = new X509EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		RSAPublicKey tPublicKey = (RSAPublicKey) tKeyFactory.generatePublic(tKeySpec);
		return tPublicKey;
	}

	public static KeyPair readRsaKeyPair() throws Exception {
		RSAPrivateKey tPrivateKey = readRsaPrivateKey(new File("../testkeys/test_rsa_pkcs8.der"));
		RSAPublicKey tPublicKey = readRsaPublicKey(new File("../testkeys/test_rsa.pub_x509.der"));
		return new KeyPair(tPublicKey, tPrivateKey);
	}

	public static PrivateKey readEd25519PrivateKey(File aFile) throws Exception {
		KeyFactory tKeyFactory = KeyFactory.getInstance("Ed25519");
		EncodedKeySpec tKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		PrivateKey tPrivateKey = tKeyFactory.generatePrivate(tKeySpec);
		return tPrivateKey;
	}

	public static PublicKey readEd25519PublicKey(File aFile) throws Exception {
		KeyFactory tKeyFactory = KeyFactory.getInstance("Ed25519");
		EncodedKeySpec tKeySpec = new X509EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		PublicKey tPublicKey = tKeyFactory.generatePublic(tKeySpec);
		return tPublicKey;
	}

	public static KeyPair readEd25519KeyPair() throws Exception {
		PrivateKey tPrivateKey = readEd25519PrivateKey(new File("../testkeys/test_ed25519_pkcs8.der"));
		PublicKey tPublicKey = readEd25519PublicKey(new File("../testkeys/test_ed25519.pub_x509.der"));
		return new KeyPair(tPublicKey, tPrivateKey);
	}
}
