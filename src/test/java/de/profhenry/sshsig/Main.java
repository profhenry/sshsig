package de.profhenry.sshsig;

import java.io.File;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author profhenry
 */
public class Main {

	public static void main(String[] someArgs) throws Exception {
		RSAPrivateKey tPrivateKey = SshKeyUtil.readPrivateKey(new File("test_rsa"));
		RSAPublicKey tPublicKey = SshKeyUtil.readPublicKey(new File("test_rsa.pub.pem"));

		SshSignatureGenerator tSignatureGenerator = SshSignatureGenerator.create(tPrivateKey, tPublicKey);
		SshSignature tSshSignature = tSignatureGenerator.generateSignature("profhenry", "carsten ist toll".getBytes());

		System.out.println(tSshSignature.dumb());
		tSshSignature.writeRawData(Path.of("generated.sig.data"));
		tSshSignature.write(Path.of("generated.sig"));
	}
}
