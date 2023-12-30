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

import java.io.PrintWriter;
import java.io.Writer;
import java.util.Base64;

/**
 * @author profhenry
 */
public class PemWriter {

	/**
	 * The default line length of the base 64 encoded content.
	 * <p>
	 * RFC7468 states that the base 64 content MUST wrap after 64 chars.
	 */
	private static final int DEFAULT_LINE_LENGTH = 64;

	private final PrintWriter printWriter;

	private final int lineLength;

	public PemWriter(Writer aWriter, int aLineLength) {
		printWriter = new PrintWriter(aWriter);
		lineLength = aLineLength;
	}

	public PemWriter(Writer aWriter) {
		this(aWriter, DEFAULT_LINE_LENGTH);
	}

	public void writeData(String aLabel, byte[] someBytes) {
		writeHeader(aLabel);
		writeData(someBytes);
		writeFooter(aLabel);
		printWriter.flush();
	}

	private void writeHeader(String aLabel) {
		printWriter.println("-----BEGIN " + aLabel + "-----");
	}

	private void writeData(byte[] someBytes) {
		String tEncoded = Base64.getEncoder().encodeToString(someBytes);

		for (int i = 0; i < tEncoded.length(); i += lineLength) {
			printWriter.println(tEncoded.substring(i, Math.min(tEncoded.length(), i + lineLength)));
		}
	}

	private void writeFooter(String aLabel) {
		printWriter.println("-----END " + aLabel + "-----");
	}
}
