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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Buffer for encoding blobs according to the SSH protocol spec.
 * <p>
 * Supported data types
 * <ul>
 * <li>integer values</li>
 * <li>byte arrays (also sub ranges/slices)</li>
 * <li>strings</li>
 * <li>{@link BigInteger}s</li>
 * <li>preambles</li>
 * <li>sequence of a string and a byte array</li>
 * </ul>
 * 
 * @author profhenry
 */
public final class SshBuffer {

	private final ByteArrayOutputStream byteArrayOutputStream;

	public SshBuffer() {
		byteArrayOutputStream = new ByteArrayOutputStream();
	}

	/**
	 * Appends a preamble.
	 * <p>
	 * Just writes the byte representation of the preamble (ASCII encoded).
	 * <p>
	 * Added bytes: number of chars
	 * 
	 * @param aPreamble the preamble
	 */
	public void appendPreamble(String aPreamble) {
		write(aPreamble);
	}

	/**
	 * Appends a string.
	 * <p>
	 * First writes an integer with the length of the string followed by the byte representation of the string (ASCII
	 * encoded).
	 * <p>
	 * Added bytes: 4 + number of chars
	 * 
	 * @param aString the string
	 */
	public void appendString(String aString) {
		write(aString.length());
		write(aString);
	}

	/**
	 * Appends a byte array.
	 * <p>
	 * First writes an integer with the length of the byte array followed by the complete content of the byte array.
	 * <p>
	 * Added bytes: 4 + length of the byte array
	 * 
	 * @param aByteArray the byte array
	 */
	public void appendByteArray(byte[] aByteArray) {
		write(aByteArray.length);
		write(aByteArray);
	}

	/**
	 * Appends a part/slice of a byte array.
	 * <p>
	 * First writes an integer with the requested length followed by the requested bytes of the byte array.
	 * <p>
	 * Added bytes: 4 + specified length
	 * 
	 * @param aByteArray the byte array
	 * @param anOffset the offset
	 * @param aLength the length
	 */
	public void appendByteArray(byte[] aByteArray, int anOffset, int aLength) {
		write(aLength);
		write(aByteArray, anOffset, aLength);
	}

	/**
	 * Appends an integer value.
	 * <p>
	 * Integer values are encoded big endian.
	 * <p>
	 * Added bytes: 4
	 * 
	 * @param anInteger the integer value
	 */
	public void appendInt(int anInteger) {
		write(anInteger);
	}

	/**
	 * Appends an {@link BigInteger}.
	 * <p>
	 * Writes the two's-complement representation (big endian encoded).
	 * <p>
	 * Added bytes: the minimal number of bytes required to represent this big integer
	 * 
	 * @param aBigInteger the big integer
	 */
	public void appendBigInteger(BigInteger aBigInteger) {
		appendByteArray(aBigInteger.toByteArray());
	}

	/**
	 * Appends a sequence of a string and a byte array.
	 * <p>
	 * First writes the overall bytes required by this sequence followed by the string and the byte array (each with
	 * their length fields as well).
	 * <p>
	 * Added bytes: 4 + 4 + number of chars + 4 + length of the byte array
	 * 
	 * @param aString the string
	 * @param aByteArray the byte array
	 */
	public void appendStringAndByteArray(String aString, byte[] aByteArray) {
		write(4 + aString.length() + 4 + aByteArray.length);
		appendString(aString);
		appendByteArray(aByteArray);
	}

	public byte[] toByteArray() {
		return byteArrayOutputStream.toByteArray();
	}

	private void write(byte[] aByteArray, int anOffset, int aLength) {
		byteArrayOutputStream.write(aByteArray, anOffset, aLength);
	}

	private void write(byte[] aByteArray) {
		write(aByteArray, 0, aByteArray.length);
	}

	private void write(String aString) {
		write(aString.getBytes(StandardCharsets.US_ASCII));
	}

	private void write(int anInt) {
		byteArrayOutputStream.write(anInt >>> 24);
		byteArrayOutputStream.write(anInt >>> 16);
		byteArrayOutputStream.write(anInt >>> 8);
		byteArrayOutputStream.write(anInt >>> 0);
	}
}
