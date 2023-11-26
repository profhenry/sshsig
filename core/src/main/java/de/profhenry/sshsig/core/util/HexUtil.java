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
