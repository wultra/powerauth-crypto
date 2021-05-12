package io.getlime.security.powerauth.crypto.lib.encryptor.model;

/**
 * Class representing a non-personalized E2EE encrypted message.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * Warning: this class will be removed in the future, use ECIES encryption for PowerAuth protocol version 3.0 or higher.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class NonPersonalizedEncryptedMessage extends EncryptedMessage {

    private byte[] applicationKey;
    private byte[] ephemeralPublicKey;

    /**
     * Get application key.
     * @return Application key.
     */
    public byte[] getApplicationKey() {
        return applicationKey;
    }

    /**
     * Set application key.
     * @param applicationKey Application key.
     */
    public void setApplicationKey(byte[] applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get ephemeral public key.
     * @return Ephemeral public key.
     */
    public byte[] getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    /**
     * Set ephemeral public key.
     * @param ephemeralPublicKey Ephemeral public key.
     */
    public void setEphemeralPublicKey(byte[] ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }
}
