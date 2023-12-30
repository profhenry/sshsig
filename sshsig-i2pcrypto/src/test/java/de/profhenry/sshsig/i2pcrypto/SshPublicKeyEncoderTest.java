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

import static org.assertj.core.api.Assertions.assertThat;

import java.security.PublicKey;
import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import de.profhenry.sshsig.core.SshPublicKeyEncoder;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Unit tests for {@link SshPublicKeyEncoder}.
 * <p>
 * 
 * @author profhenry
 */
public class SshPublicKeyEncoderTest {

	@BeforeAll
	static void setup() {
		Security.addProvider(new EdDSASecurityProvider());
	}

	@Test
	void testEncodeEd25519PublicKey() throws Exception {
		PublicKey tPublicKey = SshKeyUtil.readEd25519KeyPair().getPublic();

		SshPublicKeyEncoder tPublicKeyEncoder = new SshPublicKeyEncoder();
		byte[] tSshEncodedPublicKey = tPublicKeyEncoder.encodePublicKey(tPublicKey);

		assertThat(tSshEncodedPublicKey).asBase64Encoded()
				.isEqualTo("AAAAC3NzaC1lZDI1NTE5AAAAIDuDUZReuNqkLI5pqXRzx6+LtMtLMji2HPoDccHOE4XF");
	}
}
