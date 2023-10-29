//
// SshSignatureTest.java
//
// Copyright (C) 2023
// GEBIT Solutions GmbH
// Berlin, Dusseldorf, Leipzig, Lisbon, Stuttgart (Germany)
// All rights reserved.
//
package de.profhenry.sshsig.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.nio.file.Path;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import de.profhenry.sshsig.core.engine.Ed25519SigningEngine;
import de.profhenry.sshsig.core.engine.RsaSigningEngine;

/**
 * @author profhenry
 */
public class SshSignatureTest {

	private static RSAPrivateKey rsaPrivateKey;

	private static RSAPublicKey rsaPublicKey;

	private static EdECPrivateKey ed25519PrivateKey;

	private static EdECPublicKey ed25519PublicKey;

	@BeforeAll
	static void setup() throws Exception {
		rsaPrivateKey = SshKeyUtil.readRsaPrivateKey(new File("../testkeys/test_rsa_pkcs8.der"));
		rsaPublicKey = SshKeyUtil.readRsaPublicKey(new File("../testkeys/test_rsa.pub_x509.der"));

		ed25519PrivateKey = SshKeyUtil.readEd25519PrivateKey(new File("../testkeys/test_ed25519_pkcs8.der"));
		ed25519PublicKey = SshKeyUtil.readEd25519PublicKey(new File("../testkeys/test_ed25519.pub_x509.der"));
	}

	static class SshSignatureGeneratorProvider implements ArgumentsProvider {

		@Override
		public Stream<? extends Arguments> provideArguments(ExtensionContext aContext) throws Exception {

			List<Arguments> tList = new ArrayList<>();

			for (HashAlgorithm tHashAlgorithm : HashAlgorithm.values()) {
				for (SignatureAlgorithm tSignatureAlgorithm : SignatureAlgorithm.values()) {
					String tName = tHashAlgorithm + " + " + tSignatureAlgorithm;

					RsaSigningEngine tRsaSigningEngine =
							new RsaSigningEngine(rsaPrivateKey, rsaPublicKey, tSignatureAlgorithm);
					SshSignatureGenerator tSshSignatureGenerator =
							SshSignatureGenerator.create(tRsaSigningEngine).withHashAlgorithm(tHashAlgorithm);

					tList.add(Arguments.of(Named.of(tName, tSshSignatureGenerator)));
				}

				Ed25519SigningEngine tEd25519SigningEngine =
						new Ed25519SigningEngine(ed25519PrivateKey, ed25519PublicKey);
				String tName = tHashAlgorithm + " + ssh-ed25519";
				SshSignatureGenerator tSshSignatureGenerator =
						SshSignatureGenerator.create(tEd25519SigningEngine).withHashAlgorithm(tHashAlgorithm);

				tList.add(Arguments.of(Named.of(tName, tSshSignatureGenerator)));
			}

			return tList.stream();
		}
	}

	@ParameterizedTest
	@ArgumentsSource(SshSignatureGeneratorProvider.class)
	void testVerifyWithSshKeygen(SshSignatureGenerator aSignatureGenerator) throws Exception {

		testSignature(aSignatureGenerator, "profhenry", "This is a test message!");
	}

	private void testSignature(SshSignatureGenerator aSignatureGenerator, String aNamespace, String aMessage)
			throws Exception {
		SshSignature tSshSignature = aSignatureGenerator.generateSignature(aNamespace, aMessage.getBytes());

		String aSignatureFileName = "signature_" + aSignatureGenerator.getHashAlgorithm().getNameUsedInSshProtocol()
				+ "_" + tSshSignature.getSignatureAlgorithm() + ".sig";

		tSshSignature.write(Path.of(aSignatureFileName));

		verifyUsingSshKeygen(aMessage, aNamespace, aSignatureFileName);
	}

	private void verifyUsingSshKeygen(String aMessage, String aNamespace, String aSignatureFilename)
			throws IOException, InterruptedException {
		ProcessBuilder tProcessBuilder = new ProcessBuilder("ssh-keygen",
				"-Y",
				"verify",
				// "-vvv",
				"-f",
				"../testkeys/allowed_signers",
				"-I",
				"test@sshsig.profhenry.de",
				"-n",
				aNamespace,
				"-s",
				aSignatureFilename);

		tProcessBuilder.redirectError(Redirect.DISCARD);
		tProcessBuilder.redirectOutput(Redirect.DISCARD);

		Process tProcess = tProcessBuilder.start();

		tProcess.getOutputStream().write(aMessage.getBytes());
		tProcess.getOutputStream().close();

		int tExitCode = tProcess.waitFor();
		assertThat(tExitCode).isEqualTo(0);
	}

	// private String generateSignatureUsingSshKeygen(String aMessage) throws IOException, InterruptedException {
	// ProcessBuilder tProcessBuilder = new ProcessBuilder("ssh-keygen", "-Y", "sign", "-f", "test_rsa", "-n", "git");
	//
	// tProcessBuilder.redirectError(Redirect.INHERIT);
	// // tProcessBuilder.inheritIO();
	//
	// Process tProcess = tProcessBuilder.start();
	//
	// tProcess.getOutputStream().write(aMessage.getBytes());
	// tProcess.getOutputStream().close();
	//
	// String tSignature = new String(tProcess.getInputStream().readAllBytes());
	//
	// int tExitCode = tProcess.waitFor();
	// System.out.println(tExitCode);
	// return tSignature;
	// }
}
