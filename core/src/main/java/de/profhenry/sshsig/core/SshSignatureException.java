package de.profhenry.sshsig.core;

/**
 * Signals that an error has occured when generating a SSH signature.
 * <p>
 * 
 * @author profhenry
 */
public class SshSignatureException extends Exception {

	/**
	 * Constructs an {@code SshSignatureException} with the specified message.
	 * <p>
	 * 
	 * @param aMessage the exception message
	 */
	public SshSignatureException(String aMessage) {
		super(aMessage);
	}

	/**
	 * Constructs an {@code SshSignatureException} with the specified message and cause.
	 * 
	 * @param aMessage the exception message
	 * @param aCause   the exception which caused the error
	 */
	public SshSignatureException(String aMessage, Throwable aCause) {
		super(aMessage, aCause);
	}
}
