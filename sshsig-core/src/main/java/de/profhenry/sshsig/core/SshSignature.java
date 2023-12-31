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
 * Data container for SSH signatures.
 * <p>
 * Contains
 * <ul>
 * <li>the raw binary signature data</li>
 * <li>the used signature algorithm (as additional information)</li>
 * </ul>
 * <p>
 * This class also provides methodes for getting the textual representation in PEM format.
 * <p>
 * 
 * @author profhenry
 */
public class SshSignature {

	/**
	 * Label used in the PEM header and footer lines.
	 */
	private static final String PEM_LABEL = "SSH SIGNATURE";

	/**
	 * Line length of the base64 encoded content.
	 * <p>
	 * <b>Please note:</b><br>
	 * RFC7468 states that content MUST wrap after 64 chars<br>
	 * SSHSIG protocol states that content SHOULD wrap after 76 chars<br>
	 * However the actual OpenSSH implementation wraps after 70 chars<br>
	 * <p>
	 * We are quite confused which value to use here. It seems that the OpenSSH implementation is able to read and
	 * verify signature files no matter what value is used, but we decided to stick to the value used by OpenSSH.
	 */
	private static final int LINE_LENGTH = 70;

	/**
	 * The raw binary signature data.
	 */
	private final byte[] signatureData;

	/**
	 * The used signature algotithm.
	 * <p>
	 * This is only provided for informational purposes as this is also encoded in the raw binary data.
	 */
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

	/**
	 * Returns the textural representation in PEM format.
	 * <p>
	 * 
	 * @return string with signature in PEM format
	 */
	public String toPem() {
		StringWriter tWriter = new StringWriter();
		writeAsPem(tWriter);
		return tWriter.toString();
	}

	/**
	 * Writes the textural representation in PEM format.
	 * <p>
	 * 
	 * @param aWriter the writer
	 */
	public void writeAsPem(Writer aWriter) {
		PemWriter tPemWriter = new PemWriter(aWriter, LINE_LENGTH);
		tPemWriter.writeData(PEM_LABEL, signatureData);
	}

	/**
	 * Writes the signature to a file (in PEM format).
	 * <p>
	 * 
	 * @param aPath the path to the file
	 * @throws IOException in case wirting the signature file failed
	 */
	public void writeAsPem(Path aPath) throws IOException {
		try (BufferedWriter tWriter = Files.newBufferedWriter(aPath)) {
			writeAsPem(tWriter);
		}
	}
}
