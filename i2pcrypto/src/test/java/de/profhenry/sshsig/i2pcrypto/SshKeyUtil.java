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
package de.profhenry.sshsig.i2pcrypto;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

/**
 * @author profhenry
 */
public class SshKeyUtil {

	public static EdDSAPrivateKey readEd25519PrivateKey(File aFile) throws Exception {

		KeyFactory tKeyFactory = KeyFactory.getInstance("EdDSA", "EdDSA");
		EncodedKeySpec tKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		EdDSAPrivateKey tPrivateKey = (EdDSAPrivateKey) tKeyFactory.generatePrivate(tKeySpec);
		return tPrivateKey;
	}

	public static EdDSAPublicKey readEd25519PublicKey(File aFile) throws Exception {

		KeyFactory tKeyFactory = KeyFactory.getInstance("EdDSA", "EdDSA");
		EncodedKeySpec tKeySpec = new X509EncodedKeySpec(Files.readAllBytes(aFile.toPath()));
		EdDSAPublicKey tPublicKey = (EdDSAPublicKey) tKeyFactory.generatePublic(tKeySpec);
		return tPublicKey;
	}

	public static KeyPair readEd25519KeyPair() throws Exception {
		PrivateKey tPrivateKey = readEd25519PrivateKey(new File("../testkeys/test_ed25519_pkcs8.der"));
		PublicKey tPublicKey = readEd25519PublicKey(new File("../testkeys/test_ed25519.pub_x509.der"));
		return new KeyPair(tPublicKey, tPrivateKey);
	}
}
