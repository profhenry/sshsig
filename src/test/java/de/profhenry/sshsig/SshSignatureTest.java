//
// SshSignatureTest.java
//
// Copyright (C) 2023
// GEBIT Solutions GmbH
// Berlin, Dusseldorf, Leipzig, Lisbon, Stuttgart (Germany)
// All rights reserved.
//
package de.profhenry.sshsig;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
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

/**
 * @author profhenry
 */
public class SshSignatureTest {

	private static RSAPrivateKey privateKey;

	private static RSAPublicKey publicKey;

	@BeforeAll
	static void setup() throws Exception {
		privateKey = SshKeyUtil.readPrivateKey(new File("test_rsa"));
		publicKey = SshKeyUtil.readPublicKey(new File("test_rsa.pub.pem"));
	}

	static class SshSignatureGeneratorProvider implements ArgumentsProvider {

		@Override
		public Stream<? extends Arguments> provideArguments(ExtensionContext aContext) throws Exception {
			SshSignatureGenerator tSignatureGenerator = SshSignatureGenerator.create(privateKey, publicKey);

			List<Arguments> tList = new ArrayList<>();

			for (HashAlgorithm tHashAlgorithm : HashAlgorithm.values()) {
				for (SignatureAlgorithm tSignatureAlgorithm : SignatureAlgorithm.values()) {
					String tName = tHashAlgorithm + " + " + tSignatureAlgorithm;

					tList.add(Arguments
							.of(Named.of(tName, tSignatureGenerator.with(tHashAlgorithm).with(tSignatureAlgorithm))));
				}
			}

			return tList.stream();
		}
	}

	@ParameterizedTest
	@ArgumentsSource(SshSignatureGeneratorProvider.class)
	void testVerifyWithSshKeygen(SshSignatureGenerator aSignatureGenerator) throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, IOException, InterruptedException {

		testSignature(aSignatureGenerator, "profhenry", "This is a test message!");
	}

	private void testSignature(SshSignatureGenerator aSignatureGenerator, String aNamespace, String aMessage)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException,
			InterruptedException {
		SshSignature tSshSignature = aSignatureGenerator.generateSignature(aNamespace, aMessage.getBytes());

		String aSignatureFileName = "signature_" + aSignatureGenerator.getHashAlgorithm().getNameUsedInSshProtocol()
				+ "_" + aSignatureGenerator.getSignatureAlgorithm().getNameUsedInSshProtocol() + ".sig";

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
				"allowed_signers",
				"-I",
				"test@sshsig@profhenry.de",
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
