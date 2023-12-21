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
package de.profhenry.sshsig.core.util;

/**
 * Small util for byte to hex conversion.
 * <p>
 * Just used for logging purposes.
 * <p>
 * 
 * @author profhenry
 */
public final class HexUtil {

	private HexUtil() {
		// private constructor
	}

	/**
	 * Converts a byte array to a hex string.
	 * <p>
	 * 
	 * @param someBytes a byte array
	 * @return the string containing the hex representation of the byte array
	 */
	public static String bytesToHex(byte[] someBytes) {
		StringBuffer tBuffer = new StringBuffer();

		for (byte tByte : someBytes) {
			tBuffer.append(Character.forDigit((tByte >> 4) & 0xF, 16));
			tBuffer.append(Character.forDigit((tByte & 0xF), 16));
		}

		return tBuffer.toString();
	}
}
