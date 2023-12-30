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
package de.profhenry.sshsig.core;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author profhenry
 */
public class SshSignature {

	private static final String PEM_LABEL = "SSH SIGNATURE";

	// SSHSIG protocol states that content SHOULD wrap after 76 chars
	// However the actual OpenSSH implementation wraps after 70 chars
	private static final int LINE_LENGTH = 70;

	private final byte[] signatureData;

	private final SignatureAlgorithm signatureAlgorithm;

	public SshSignature(byte[] someSignatureData, SignatureAlgorithm aSignatureAlgorithm) {
		signatureData = someSignatureData;
		signatureAlgorithm = aSignatureAlgorithm;
	}

	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public byte[] getSignatureData() {
		return signatureData;
	}

	public String toPem() {
		StringWriter tWriter = new StringWriter();
		writeAsPem(tWriter);
		return tWriter.toString();
	}

	public void writeAsPem(Writer aWriter) {
		PemWriter tPemWriter = new PemWriter(aWriter, LINE_LENGTH);
		tPemWriter.writeData(PEM_LABEL, signatureData);
	}

	public void writeAsPem(Path aPath) throws IOException {
		try (BufferedWriter tWriter = Files.newBufferedWriter(aPath)) {
			writeAsPem(tWriter);
		}
	}
}
