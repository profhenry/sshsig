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
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;

import de.profhenry.sshsig.core.engine.SigningEngine.SigningResult;

/**
 * @author profhenry
 */
public class Ed25519SigningEngine implements SigningEngine {

	private final EdECPrivateKey privateKey;

	private final EdECPublicKey publicKey;

	public Ed25519SigningEngine(EdECPrivateKey aPrivateKey, EdECPublicKey aPublicKey) {
		privateKey = aPrivateKey;
		publicKey = aPublicKey;
	}

	@Override
	public SigningResult sign(byte[] aSomeDataToSign)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

		SigningResult tSigningResult = new SigningResult();
		tSigningResult.publicKey = writePublicKey();
		tSigningResult.signatureAlgorithm = "ssh-ed25519";
		tSigningResult.signedContent = sign0(aSomeDataToSign);
		return tSigningResult;
	}

	private byte[] writePublicKey() throws IOException {
		ByteArrayOutputStream tOut = new ByteArrayOutputStream();
		DataOutputStream tDataStream = new DataOutputStream(tOut);

		tDataStream.writeInt(11);
		tDataStream.writeBytes("ssh-ed25519");
		tDataStream.writeInt(32);
		tDataStream.write(publicKey.getEncoded(), 12, 32);
		// tDataStream.write(tempReadECPublicKey.getPoint().getY().toByteArray());

		tDataStream.flush();
		return tOut.toByteArray();
	}

	private byte[] sign0(byte[] someBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature tSignature = Signature.getInstance("ed25519");
		tSignature.initSign(privateKey);
		tSignature.update(someBytes);
		byte[] tempSignedData = tSignature.sign();

		return tempSignedData;
	}
}
