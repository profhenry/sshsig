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

import static org.assertj.core.api.Assertions.assertThat;

import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import de.profhenry.sshsig.core.SshPublicKeyEncoder;

/**
 * Unit tests for {@link SshPublicKeyEncoder}.
 * <p>
 * 
 * @author profhenry
 */
public class SshPublicKeyEncoderTest {

	@BeforeAll
	static void setup() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	@Disabled
	void testEncodeDsaPublicKey() throws Exception {
		PublicKey tPublicKey = SshKeyUtil.readDsaKeyPair().getPublic();

		SshPublicKeyEncoder tPublicKeyEncoder = new SshPublicKeyEncoder();
		byte[] tSshEncodedPublicKey = tPublicKeyEncoder.encodePublicKey(tPublicKey);

		assertThat(tSshEncodedPublicKey).asBase64Encoded()
				.isEqualTo(
						"AAAAB3NzaC1kc3MAAACBAP8BC5pi3uxvOtlb1ikWNeLUubiaT0l7aMOhAbOFmtivswcg0r+rZiX/UOjhxCATRiaTXV42byLnf0cKzQrZ5QEnm8uTf1aK0gdT/bdQaZwWmkMB2LdHQ4xEt3slsDLYoXwwzV+stpRcFQ1VyUlJQV754HqHZT8RbkUBJHIsIqslAAAAFQCKvLgJmuxvJy6DvdRB5Fm/VZR5PwAAAIEA1y5UQItEth5WSS6166Aujc+7x9jgaztoC4Uo0iskMM5D0oVrJSyVwCAOcNPEeya4zNnJgkD16Wco3XOryBcgjWScEoTgict2J8rnaUWDkyOMptfbiF+oU39INh3m+2tvIfsgX81bAQJD0STYiF9J3G/PQYjvRIxhybtHJHGcuaUAAACBANTDVZW7LC9PbzQ1e2SxMOznf76/WV8RfwfKALh0DpJvyaEuOQkgwO/AzSNoN1mJgkn7mjXKgsJLYB/49d1arv8n/nG+7oLGdKYlKlXOkJ2bW+yxnFwLvBTBniCbdyylPP1iNbw2SArns44xxBszjTedAZcpJQiv+ThZI3Bzg5dM");
	}

	@Test
	void testEncodeRsaPublicKey() throws Exception {
		PublicKey tPublicKey = SshKeyUtil.readRsaKeyPair().getPublic();

		SshPublicKeyEncoder tPublicKeyEncoder = new SshPublicKeyEncoder();
		byte[] tSshEncodedPublicKey = tPublicKeyEncoder.encodePublicKey(tPublicKey);

		assertThat(tSshEncodedPublicKey).asBase64Encoded()
				.isEqualTo(
						"AAAAB3NzaC1yc2EAAAADAQABAAABgQDg9Lf347GyGfq+SZjWnLEFY61tz3czkkpeU71piNtCD9M18vsonIKmLRwUC4dKBE+UJQf7F79Mx/Z6XqgNCTP9tAVj1YMKtIIXbl6F4hkMWZr1XTjq78jCk3yWx7BA9CYaTxK185l3WbcZovrx9iTrVafi6+cXhxAC4HYHQYjB/1YubPhWIJ4mtqo7e22xP84Kdr/aYmSJbx0vaUjRJQaFJkYVi2Sb8GYAagd5YQ5aODU6CuY/ycp18UMQ56G/uSR19O+OGXrHbF2GEZTko6ESOAbu7EjquU1fOL3xeh/3GYNtYjeztQFCXGz2iXrKNk+wMjHGvrg8w11NdgpT983UMwA8bV8kctz4qaH/89HhR49pkLSxOc9AMzjSL8N4bueId598KnfutEzT0N+Ghwsi+1fDrohCTRx2x+PyLYe5syehjn/IxhnQlKEvtRitjUqCn32mAufx2BbCl8rykPTUxBE/QAUYPlA/Surv8j9yE8tEpDIdEBc78kpwBxH60p8=");
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
