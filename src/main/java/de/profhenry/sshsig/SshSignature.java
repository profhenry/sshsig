package de.profhenry.sshsig;

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

	public SshSignature(byte[] someSignatureData) {
		signatureData = someSignatureData;
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

	private static void splitAfterFixedNumberOfChars(String aString, int aSize, Consumer<String> aConsumer) {
		for (int i = 0; i < aString.length(); i += aSize) {
			aConsumer.accept(aString.substring(i, Math.min(aString.length(), i + aSize)));
		}
	}
}
