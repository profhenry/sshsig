//
// RsaSigningEngine.java
//
// Copyright (C) 2023
// GEBIT Solutions GmbH
// Berlin, Dusseldorf, Leipzig, Lisbon, Stuttgart (Germany)
// All rights reserved.
//
package de.profhenry.sshsig.core.engine;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import de.profhenry.sshsig.core.SignatureAlgorithm;
import de.profhenry.sshsig.core.engine.SigningEngine.SigningResult;

/**
 * @author profhenry
 */
public class RsaSigningEngine implements SigningEngine {

	private final RSAPrivateKey privateKey;

	private final RSAPublicKey publicKey;

	private final SignatureAlgorithm signatureAlgorithm;

	public RsaSigningEngine(RSAPrivateKey aPrivateKey, RSAPublicKey aPublicKey,
			SignatureAlgorithm aSignatureAlgorithm) {
		privateKey = aPrivateKey;
		publicKey = aPublicKey;
		signatureAlgorithm = aSignatureAlgorithm;
	}

	@Override
	public SigningResult sign(byte[] aSomeDataToSign)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

		SigningResult tSigningResult = new SigningResult();
		tSigningResult.publicKey = writePublicKey();
		tSigningResult.signatureAlgorithm = signatureAlgorithm.getNameUsedInSshProtocol();
		tSigningResult.signedContent = sign0(aSomeDataToSign);
		return tSigningResult;
	}

	private byte[] writePublicKey() throws IOException {
		ByteArrayOutputStream tOut = new ByteArrayOutputStream();
		DataOutputStream tDataStream = new DataOutputStream(tOut);

		// public key
		tDataStream.writeInt(7);
		tDataStream.writeBytes("ssh-rsa");
		tDataStream.writeInt(publicKey.getPublicExponent().toByteArray().length);
		tDataStream.write(publicKey.getPublicExponent().toByteArray());
		tDataStream.writeInt(publicKey.getModulus().toByteArray().length);
		tDataStream.write(publicKey.getModulus().toByteArray());

		tDataStream.flush();
		return tOut.toByteArray();
	}

	private byte[] sign0(byte[] someBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature tSignature = Signature.getInstance(signatureAlgorithm.getSignatureName());
		tSignature.initSign(privateKey);
		tSignature.update(someBytes);
		byte[] tempSignedData = tSignature.sign();

		return tempSignedData;
	}
}
