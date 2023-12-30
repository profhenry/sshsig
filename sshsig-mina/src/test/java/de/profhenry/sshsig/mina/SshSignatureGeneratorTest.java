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
package de.profhenry.sshsig.mina;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.local.AgentImpl;
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
	class Dsa {

		private SshAgent sshAgent;

		private PublicKey publicKey;

		@BeforeEach
		void setup() throws Exception {
			sshAgent = new AgentImpl();
			KeyPair tKeyPair = SshKeyUtil.readDsaKeyPair();
			sshAgent.addIdentity(tKeyPair, "test_dsa");
			publicKey = tKeyPair.getPublic();
		}

		@Nested
		class Sha256 {

			private SshSignatureGenerator<PublicKey> sshSignatureGenerator;

			@BeforeEach
			void setup() throws Exception {
				sshSignatureGenerator = SshSignatureGenerator.create()
						.withSigningBackend(new ApacheMinaSshAgentEngine(sshAgent))
						.withHashAlgorithm(HashAlgorithm.SHA_256);
			}

			// @formatter:off
			private static final String EXPECTED_SIGNATURE_START =
				  "U1NIU0lHAAAAAQAAAbMAAAAHc3NoLWRzcwAAAIEA/wELmmLe7G862VvWKRY14tS5uJpPSX"
				+ "tow6EBs4Wa2K+zByDSv6tmJf9Q6OHEIBNGJpNdXjZvIud/RwrNCtnlASeby5N/VorSB1P9"
				+ "t1BpnBaaQwHYt0dDjES3eyWwMtihfDDNX6y2lFwVDVXJSUlBXvngeodlPxFuRQEkciwiqy"
				+ "UAAAAVAIq8uAma7G8nLoO91EHkWb9VlHk/AAAAgQDXLlRAi0S2HlZJLrXroC6Nz7vH2OBr"
				+ "O2gLhSjSKyQwzkPShWslLJXAIA5w08R7JrjM2cmCQPXpZyjdc6vIFyCNZJwShOCJy3Ynyu"
				+ "dpRYOTI4ym19uIX6hTf0g2Heb7a28h+yBfzVsBAkPRJNiIX0ncb89BiO9EjGHJu0ckcZy5"
				+ "pQAAAIEA1MNVlbssL09vNDV7ZLEw7Od/vr9ZXxF/B8oAuHQOkm/JoS45CSDA78DNI2g3WY"
				+ "mCSfuaNcqCwktgH/j13Vqu/yf+cb7ugsZ0piUqVc6QnZtb7LGcXAu8FMGeIJt3LKU8/WI1"
				+ "vDZICuezjjHEGzONN50BlyklCK/5OFkjcHODl0wAAAAEdGVzdAAAAAAAAAAGc2hhMjU2AA"
				+ "AANwAAAAdzc2gtZHNz";
			// @formatter:on

			@Test
			void testSignString() throws Exception {
				String tMessage = MESSAGE;
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tMessage);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().startsWith(EXPECTED_SIGNATURE_START);
			}

			@Test
			void testSignByteArray() throws SshSignatureException {
				byte[] tByteArray = MESSAGE.getBytes();
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tByteArray);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().startsWith(EXPECTED_SIGNATURE_START);
			}

			@Test
			void testSignFile() throws IOException, SshSignatureException {
				File tFile = new File("../message.txt");
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tFile);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().startsWith(EXPECTED_SIGNATURE_START);
			}

			@Test
			void testSignInputStream() throws IOException, SshSignatureException {
				InputStream tInputStream = new ByteArrayInputStream(MESSAGE.getBytes());
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tInputStream);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().startsWith(EXPECTED_SIGNATURE_START);
			}

			@Test
			void testVerifyWithSshKeyGen() throws SshSignatureException, IOException, InterruptedException {
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, MESSAGE);
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

			private SshSignatureGenerator<PublicKey> sshSignatureGenerator;

			@BeforeEach
			void setup() throws Exception {
				sshSignatureGenerator =
						SshSignatureGenerator.create().withSigningBackend(new ApacheMinaSshAgentEngine(sshAgent));
			}

			// @formatter:off
			private static final String EXPECTED_SIGNATURE_START =
				  "U1NIU0lHAAAAAQAAAbMAAAAHc3NoLWRzcwAAAIEA/wELmmLe7G862VvWKRY14tS5uJpPSX"
				+ "tow6EBs4Wa2K+zByDSv6tmJf9Q6OHEIBNGJpNdXjZvIud/RwrNCtnlASeby5N/VorSB1P9"
				+ "t1BpnBaaQwHYt0dDjES3eyWwMtihfDDNX6y2lFwVDVXJSUlBXvngeodlPxFuRQEkciwiqy"
				+ "UAAAAVAIq8uAma7G8nLoO91EHkWb9VlHk/AAAAgQDXLlRAi0S2HlZJLrXroC6Nz7vH2OBr"
				+ "O2gLhSjSKyQwzkPShWslLJXAIA5w08R7JrjM2cmCQPXpZyjdc6vIFyCNZJwShOCJy3Ynyu"
				+ "dpRYOTI4ym19uIX6hTf0g2Heb7a28h+yBfzVsBAkPRJNiIX0ncb89BiO9EjGHJu0ckcZy5"
				+ "pQAAAIEA1MNVlbssL09vNDV7ZLEw7Od/vr9ZXxF/B8oAuHQOkm/JoS45CSDA78DNI2g3WY"
				+ "mCSfuaNcqCwktgH/j13Vqu/yf+cb7ugsZ0piUqVc6QnZtb7LGcXAu8FMGeIJt3LKU8/WI1"
				+ "vDZICuezjjHEGzONN50BlyklCK/5OFkjcHODl0wAAAAEdGVzdAAAAAAAAAAGc2hhNTEyAA"
				+ "AANwAAAAdzc2gtZHNz";
			// @formatter:on

			@Test
			void testSignString() throws Exception {
				String tMessage = MESSAGE;
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tMessage);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().startsWith(EXPECTED_SIGNATURE_START);
			}

			@Test
			void testSignByteArray() throws SshSignatureException {
				byte[] tByteArray = MESSAGE.getBytes();
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tByteArray);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().startsWith(EXPECTED_SIGNATURE_START);
			}

			@Test
			void testSignFile() throws IOException, SshSignatureException {
				File tFile = new File("../message.txt");
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tFile);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().startsWith(EXPECTED_SIGNATURE_START);
			}

			@Test
			void testSignInputStream() throws IOException, SshSignatureException {
				InputStream tInputStream = new ByteArrayInputStream(MESSAGE.getBytes());
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tInputStream);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().startsWith(EXPECTED_SIGNATURE_START);
			}

			@Test
			void testVerifyWithSshKeyGen() throws SshSignatureException, IOException, InterruptedException {
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, MESSAGE);
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

	@Nested
	class Rsa {

		private SshAgent sshAgent;

		private PublicKey publicKey;

		@BeforeEach
		void setup() throws Exception {
			sshAgent = new AgentImpl();
			KeyPair tKeyPair = SshKeyUtil.readRsaKeyPair();
			sshAgent.addIdentity(tKeyPair, "test_rsa");
			publicKey = tKeyPair.getPublic();
		}

		@Nested
		class Sha256 {

			private SshSignatureGenerator<PublicKey> sshSignatureGenerator;

			@BeforeEach
			void setup() throws Exception {
				sshSignatureGenerator = SshSignatureGenerator.create()
						.withSigningBackend(new ApacheMinaSshAgentEngine(sshAgent))
						.withHashAlgorithm(HashAlgorithm.SHA_256);
			}

			// @formatter:off
			private static final String EXPECTED_SIGNATURE =
				  "U1NIU0lHAAAAAQAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAOD0t/fjsbIZ+r5JmNacsQ"
				+ "VjrW3PdzOSSl5TvWmI20IP0zXy+yicgqYtHBQLh0oET5QlB/sXv0zH9npeqA0JM/20BWPV"
				+ "gwq0ghduXoXiGQxZmvVdOOrvyMKTfJbHsED0JhpPErXzmXdZtxmi+vH2JOtVp+Lr5xeHEA"
				+ "LgdgdBiMH/Vi5s+FYgnia2qjt7bbE/zgp2v9piZIlvHS9pSNElBoUmRhWLZJvwZgBqB3lh"
				+ "Dlo4NToK5j/JynXxQxDnob+5JHX0744ZesdsXYYRlOSjoRI4Bu7sSOq5TV84vfF6H/cZg2"
				+ "1iN7O1AUJcbPaJeso2T7AyMca+uDzDXU12ClP3zdQzADxtXyRy3Pipof/z0eFHj2mQtLE5"
				+ "z0AzONIvw3hu54h3n3wqd+60TNPQ34aHCyL7V8OuiEJNHHbH4/Ith7mzJ6GOf8jGGdCUoS"
				+ "+1GK2NSoKffaYC5/HYFsKXyvKQ9NTEET9ABRg+UD9K6u/yP3ITy0SkMh0QFzvySnAHEfrS"
				+ "nwAAAAR0ZXN0AAAAAAAAAAZzaGEyNTYAAAGUAAAADHJzYS1zaGEyLTUxMgAAAYB0YEykEV"
				+ "XyzQnti5FLFQGWgsgstKeavITXOhlVBSsMASWoAVH1UWxT715H/lzJviyrozbqYJ6gMYzN"
				+ "LTBHjMtFfXWnNroNqO4+KVRiGkbPvOvGruiVUDWm+rEZmrBzWesw3S+DOGBhkyz+vjkx5S"
				+ "jPl1QTuJAHfeu1BEn/4BrHG6x9QyhHiU6rN3zfLE3JtUbKChkilzS/tOtCDPHxpabB+8uS"
				+ "rPxE0knqWZjs8/ZuEtU06e4MJueGYcGbEOgHXSGNS/iLk86JaL8ihBjYcYlycTOjF4SjNz"
				+ "e/HW8yxZs9C6jZOkcZhR3rhMNn1GJU2uOhXlODAx6Y1v71sIQbQmquF+LGmcRKWtdpw3/o"
				+ "M91GLvRj/ICGc+Jk6qI+TBKujjtrc+joabFbZwIPYviwfTEz4rDCmgnmN32IPA1mkBbEX8"
				+ "dUbdbNoWsnb2mUjHWSTrsZ4zkjBXDz5KU4FpUkimNiKGj812lHeZPjFzj/a1vm48VnZNVg"
				+ "OW26Dyfdo6a3tco=";
			// @formatter:on

			@Test
			void testSignString() throws SshSignatureException {
				String tMessage = MESSAGE;
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tMessage);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignByteArray() throws SshSignatureException {
				byte[] tByteArray = MESSAGE.getBytes();
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tByteArray);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignFile() throws IOException, SshSignatureException {
				File tFile = new File("../message.txt");
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tFile);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignInputStream() throws IOException, SshSignatureException {
				InputStream tInputStream = new ByteArrayInputStream(MESSAGE.getBytes());
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tInputStream);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testVerifyWithSshKeyGen() throws SshSignatureException, IOException, InterruptedException {
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, MESSAGE);
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

			private SshSignatureGenerator<PublicKey> sshSignatureGenerator;

			@BeforeEach
			void setup() throws Exception {
				sshSignatureGenerator =
						SshSignatureGenerator.create().withSigningBackend(new ApacheMinaSshAgentEngine(sshAgent));
			}

			// @formatter:off
			private static final String EXPECTED_SIGNATURE =
				  "U1NIU0lHAAAAAQAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAOD0t/fjsbIZ+r5JmNacsQ"
				+ "VjrW3PdzOSSl5TvWmI20IP0zXy+yicgqYtHBQLh0oET5QlB/sXv0zH9npeqA0JM/20BWPV"
				+ "gwq0ghduXoXiGQxZmvVdOOrvyMKTfJbHsED0JhpPErXzmXdZtxmi+vH2JOtVp+Lr5xeHEA"
				+ "LgdgdBiMH/Vi5s+FYgnia2qjt7bbE/zgp2v9piZIlvHS9pSNElBoUmRhWLZJvwZgBqB3lh"
				+ "Dlo4NToK5j/JynXxQxDnob+5JHX0744ZesdsXYYRlOSjoRI4Bu7sSOq5TV84vfF6H/cZg2"
				+ "1iN7O1AUJcbPaJeso2T7AyMca+uDzDXU12ClP3zdQzADxtXyRy3Pipof/z0eFHj2mQtLE5"
				+ "z0AzONIvw3hu54h3n3wqd+60TNPQ34aHCyL7V8OuiEJNHHbH4/Ith7mzJ6GOf8jGGdCUoS"
				+ "+1GK2NSoKffaYC5/HYFsKXyvKQ9NTEET9ABRg+UD9K6u/yP3ITy0SkMh0QFzvySnAHEfrS"
				+ "nwAAAAR0ZXN0AAAAAAAAAAZzaGE1MTIAAAGUAAAADHJzYS1zaGEyLTUxMgAAAYDSaZIO9J"
				+ "8a1yrbyLSBdB0fWQQfIjquU4Dl5yQFALjkCo5hNEpVQw614H4xbHvNYpIHmvyobcdGLcwM"
				+ "vur6FCUUQzNLSxV1PwUrgxuQwXKVx6KohqOGXbFIsPOEAi20gJIHP0Di7+wHbTXEa1+kTg"
				+ "wcYlP89PTP999RvVJ1givH2Aa2tGVD7MnNxC3gsJC847Sh4zHfOMFSuaOAW6pXkitSgE6r"
				+ "/RnoGy82WE4BHqUHw2xWwNkqhXjCWA4xsRvTXWvT+rA93QVRgGjFp6W3rvZS74Ah6SAXqB"
				+ "XCmP9GJ+clHZJrtGNSemcGla2rP9VQBAYxMLI33y24NALxtfsfch7SidWDIBBRjF9Iq28/"
				+ "yeJpfElyGT6r8T1d8eeDE/99tVX5Ern/cP7gpXMCQ1WOkqh24D4I/R+u3qVjVISlDy2N30"
				+ "w0nSMGHouI2XO2pCFqwfos6rQO2onMT8kZ44LgBPI5hc9Rm5uw6B+/ufAyGK/rm2Yf9NPJ"
				+ "NcLY5/6Nqq95e4Y=";
			// @formatter:on

			@Test
			void testSignString() throws SshSignatureException {
				String tMessage = MESSAGE;
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tMessage);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignByteArray() throws SshSignatureException {
				byte[] tByteArray = MESSAGE.getBytes();
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tByteArray);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignFile() throws IOException, SshSignatureException {
				File tFile = new File("../message.txt");
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tFile);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignInputStream() throws IOException, SshSignatureException {
				InputStream tInputStream = new ByteArrayInputStream(MESSAGE.getBytes());
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tInputStream);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testVerifyWithSshKeyGen() throws SshSignatureException, IOException, InterruptedException {
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, MESSAGE);
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

	@Nested
	class Ed25519 {

		private SshAgent sshAgent;

		private PublicKey publicKey;

		@BeforeEach
		void setup() throws Exception {
			sshAgent = new AgentImpl();
			KeyPair tKeyPair = SshKeyUtil.readEd25519KeyPair();
			sshAgent.addIdentity(tKeyPair, "test_ed25519");
			publicKey = tKeyPair.getPublic();
		}

		@Nested
		class Sha256 {

			private SshSignatureGenerator<PublicKey> sshSignatureGenerator;

			@BeforeEach
			void setup() throws Exception {
				sshSignatureGenerator = SshSignatureGenerator.create()
						.withSigningBackend(new ApacheMinaSshAgentEngine(sshAgent))
						.withHashAlgorithm(HashAlgorithm.SHA_256);
			}

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
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tMessage);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignByteArray() throws SshSignatureException {
				byte[] tByteArray = MESSAGE.getBytes();
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tByteArray);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignFile() throws IOException, SshSignatureException {
				File tFile = new File("../message.txt");
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tFile);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignInputStream() throws IOException, SshSignatureException {
				InputStream tInputStream = new ByteArrayInputStream(MESSAGE.getBytes());
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tInputStream);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testVerifyWithSshKeyGen() throws SshSignatureException, IOException, InterruptedException {
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, MESSAGE);
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

			private SshSignatureGenerator<PublicKey> sshSignatureGenerator;

			@BeforeEach
			void setup() throws Exception {
				sshSignatureGenerator =
						SshSignatureGenerator.create().withSigningBackend(new ApacheMinaSshAgentEngine(sshAgent));
			}

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
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tMessage);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignByteArray() throws SshSignatureException {
				byte[] tByteArray = MESSAGE.getBytes();
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tByteArray);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignFile() throws IOException, SshSignatureException {
				File tFile = new File("../message.txt");
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tFile);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testSignInputStream() throws IOException, SshSignatureException {
				InputStream tInputStream = new ByteArrayInputStream(MESSAGE.getBytes());
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, tInputStream);
				assertThat(tSignature.getSignatureData()).asBase64Encoded().isEqualTo(EXPECTED_SIGNATURE);
			}

			@Test
			void testVerifyWithSshKeyGen() throws SshSignatureException, IOException, InterruptedException {
				SshSignature tSignature = sshSignatureGenerator.generateSignature(publicKey, NAMESPACE, MESSAGE);
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
