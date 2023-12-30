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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import de.profhenry.sshsig.core.HashAlgorithm;
import de.profhenry.sshsig.core.SshSignature;
import de.profhenry.sshsig.core.SshSignatureException;
import de.profhenry.sshsig.core.SshSignatureGenerator;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * @author profhenry
 */
public class SshSignatureGeneratorTest {

	private static final String MESSAGE = "This is a test message!";

	private static final String NAMESPACE = "test";

	@BeforeAll
	static void setup() {
		Security.addProvider(new EdDSASecurityProvider());
	}

	@Nested
	class Ed25519 {

		private KeyPair keyPair;

		@BeforeEach
		void setup() throws Exception {
			keyPair = SshKeyUtil.readEd25519KeyPair();
		}

		@Nested
		class Sha256 {

			private SshSignatureGenerator<KeyPair> sshSignatureGenerator =
					SshSignatureGenerator.create().withHashAlgorithm(HashAlgorithm.SHA_256);

			// @formatter:off
			private static final String EXPECTED_SIGNATURE =
				  "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgO4NRlF642qQsjmmpdHPHr4u0y0"
				+ "syOLYc+gNxwc4ThcUAAAAEdGVzdAAAAAAAAAAGc2hhMjU2AAAAUwAAAAtzc2gtZWQyNTUx"
				+ "OQAAAEB6eAR6l/CO1z6Zii5/gOyTaw8blF/WkZn7lQ7GWKMwz8fRb11XlCzZeRnT+3oCxE"
				+ "FmtbdzXmf5ClT1exukikYM";
			// @formatter:on

			@Test
			void testSignString() throws SshSignatureException {
				String tMessage = MESSAGE;
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, tMessage);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignByteArray() throws SshSignatureException {
				byte[] tByteArray = MESSAGE.getBytes();
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, tByteArray);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignFile() throws IOException, SshSignatureException {
				File tFile = new File("../message.txt");
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, tFile);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignInputStream() throws IOException, SshSignatureException {
				InputStream tInputStream = new ByteArrayInputStream(MESSAGE.getBytes());
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, tInputStream);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testVerifyWithSshKeyGen() throws SshSignatureException, IOException, InterruptedException {
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, MESSAGE);
				String tSignatureFileName = "test."
						+ tSignature.getSignatureAlgorithm()
						+ "."
						+ sshSignatureGenerator.getHashAlgorithm()
						+ ".sig";
				tSignature.writeAsPem(Paths.get(tSignatureFileName));

				verifyUsingSshKeygen(MESSAGE, NAMESPACE, tSignatureFileName);
			}
		}

		@Nested
		class Sha512 {

			private SshSignatureGenerator<KeyPair> sshSignatureGenerator = SshSignatureGenerator.create();

			// @formatter:off
			private static final String EXPECTED_SIGNATURE =
				  "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgO4NRlF642qQsjmmpdHPHr4u0y0"
				+ "syOLYc+gNxwc4ThcUAAAAEdGVzdAAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx"
				+ "OQAAAECXeYiP4lfCx6Yt5lt2IenH6Y5G5r1u7/TQUNk+32RQBOzxK3EtpKD0lhGHCHjGV5"
				+ "O9tQmZwa6y/cen3W8Ic9MD";
			// @formatter:on

			@Test
			void testSignString() throws SshSignatureException {
				String tMessage = MESSAGE;
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, tMessage);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignByteArray() throws SshSignatureException {
				byte[] tByteArray = MESSAGE.getBytes();
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, tByteArray);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignFile() throws IOException, SshSignatureException {
				File tFile = new File("../message.txt");
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, tFile);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignInputStream() throws IOException, SshSignatureException {
				InputStream tInputStream = new ByteArrayInputStream(MESSAGE.getBytes());
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, tInputStream);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testVerifyWithSshKeyGen() throws SshSignatureException, IOException, InterruptedException {
				SshSignature tSignature = sshSignatureGenerator.generateSignature(keyPair, NAMESPACE, MESSAGE);
				String tSignatureFileName = "test."
						+ tSignature.getSignatureAlgorithm()
						+ "."
						+ sshSignatureGenerator.getHashAlgorithm()
						+ ".sig";
				tSignature.writeAsPem(Paths.get(tSignatureFileName));

				verifyUsingSshKeygen(MESSAGE, NAMESPACE, tSignatureFileName);
			}
		}
	}

	private void verifyUsingSshKeygen(String aMessage, String aNamespace, String aSignatureFilename)
			throws IOException, InterruptedException {
		ProcessBuilder tProcessBuilder = new ProcessBuilder("ssh-keygen",
				"-Y",
				"verify",
				"-vvv",
				"-f",
				"../testkeys/allowed_signers",
				"-I",
				"test@sshsig.profhenry.de",
				"-n",
				aNamespace,
				"-s",
				aSignatureFilename);

		// tProcessBuilder.redirectOutput(Redirect.INHERIT);
		// tProcessBuilder.redirectError(Redirect.INHERIT);

		Process tProcess = tProcessBuilder.start();

		tProcess.getOutputStream().write(aMessage.getBytes());
		tProcess.getOutputStream().close();

		int tExitCode = tProcess.waitFor();
		assertThat(tExitCode).isEqualTo(0);
	}
}
