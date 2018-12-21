package io.getlime.security.powerauth.crypto.lib.encryptor.model;

/**
 * Class representing a non-personalized E2EE encrypted message.
 *
 * <h5>PowerAuth protocol versions:</h5>
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

    public byte[] getApplicationKey() {
        return applicationKey;
    }

    public void setApplicationKey(byte[] applicationKey) {
        this.applicationKey = applicationKey;
    }

    public byte[] getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(byte[] ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }
}
