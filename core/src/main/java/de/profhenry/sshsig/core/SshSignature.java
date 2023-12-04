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
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.function.Consumer;

/**
 * @author profhenry
 */
public class SshSignature {

	private static final String HEADER = "-----BEGIN SSH SIGNATURE-----";

	private static final String FOOTER = "-----END SSH SIGNATURE-----";

	private static final int MAX_LINE_LENGTH = 70;

	private final byte[] signatureData;

	private final SignatureAlgorithm signatureAlgorithm;

	public SshSignature(byte[] someSignatureData, SignatureAlgorithm aSignatureAlgorithm) {
		signatureData = someSignatureData;
		signatureAlgorithm = aSignatureAlgorithm;
	}

	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	private void write(Writer aWriter) {
		PrintWriter tPrintWriter = new PrintWriter(aWriter);

		tPrintWriter.println(HEADER);
		String tEncoded = Base64.getEncoder().encodeToString(signatureData);
		splitAfterFixedNumberOfChars(tEncoded, MAX_LINE_LENGTH, tPrintWriter::println);
		tPrintWriter.println(FOOTER);
		tPrintWriter.flush();
	}

	public String dumb() {
		StringWriter tWriter = new StringWriter();
		write(tWriter);
		return tWriter.toString();
	}

	public void write(OutputStream anOutputStream) {
		OutputStreamWriter tWriter = new OutputStreamWriter(anOutputStream);
		write(tWriter);
	}

	public void write(Path aPath) throws IOException {
		BufferedWriter tWriter = Files.newBufferedWriter(aPath);
		write(tWriter);
	}

	public void writeRawData(Path aPath) throws IOException {
		Files.write(aPath, signatureData);
	}

	public byte[] getSignatureData() {
		return signatureData;
	}

	private static void splitAfterFixedNumberOfChars(String aString, int aSize, Consumer<String> aConsumer) {
		for (int i = 0; i < aString.length(); i += aSize) {
			aConsumer.accept(aString.substring(i, Math.min(aString.length(), i + aSize)));
		}
	}
}
