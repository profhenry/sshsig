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
package de.profhenry.sshsig.bcprov;

import java.io.File;
import java.io.FileReader;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.EncodedKeySpec;

import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * @author profhenry
 */
public class SshKeyUtil {

	private static PrivateKey readPrivateKey(String anAlgorithm, File aFile) throws Exception {
		KeyFactory tKeyFactory = KeyFactory.getInstance(anAlgorithm, "BC");
		try (FileReader tFileReader = new FileReader(aFile); PemReader tPemReader = new PemReader(tFileReader)) {
			PemObject tPemObject = tPemReader.readPemObject();
			EncodedKeySpec tKeySpec = new OpenSSHPrivateKeySpec(tPemObject.getContent());
			return tKeyFactory.generatePrivate(tKeySpec);
		}
	}

	private static PublicKey readPublicKey(String anAlgorithm, File aFile) throws Exception {
		KeyFactory tKeyFactory = KeyFactory.getInstance(anAlgorithm, "BC");
		EncodedKeySpec tKeySpec =
				new OpenSSHPublicKeySpec(Base64.decode(new String(Files.readAllBytes(aFile.toPath())).split(" ")[1]));
		return tKeyFactory.generatePublic(tKeySpec);
	}

	public static KeyPair readDsaKeyPair() throws Exception {
		PrivateKey tPrivateKey = readPrivateKey("DSA", new File("../testkeys/test_dsa"));
		PublicKey tPublicKey = readPublicKey("DSA", new File("../testkeys/test_dsa.pub"));
		return new KeyPair(tPublicKey, tPrivateKey);
	}

	public static KeyPair readRsaKeyPair() throws Exception {
		PrivateKey tPrivateKey = readPrivateKey("RSA", new File("../testkeys/test_rsa"));
		PublicKey tPublicKey = readPublicKey("RSA", new File("../testkeys/test_rsa.pub"));
		return new KeyPair(tPublicKey, tPrivateKey);
	}

	public static KeyPair readEd25519KeyPair() throws Exception {
		PrivateKey tPrivateKey = readPrivateKey("Ed25519", new File("../testkeys/test_ed25519"));
		PublicKey tPublicKey = readPublicKey("Ed25519", new File("../testkeys/test_ed25519.pub"));
		return new KeyPair(tPublicKey, tPrivateKey);
	}

	public static DSAPrivateKey readDsaPrivateKey(File aFile) throws Exception {
		KeyFactory tKeyFactory = KeyFactory.getInstance("DSA");
		try (FileReader tFileReader = new FileReader(aFile); PemReader tPemReader = new PemReader(tFileReader)) {
			PemObject tPemObject = tPemReader.readPemObject();
			EncodedKeySpec tKeySpec = new OpenSSHPrivateKeySpec(tPemObject.getContent());
			DSAPrivateKey tPrivateKey = (DSAPrivateKey) tKeyFactory.generatePrivate(tKeySpec);
			return tPrivateKey;
		}
	}
}
