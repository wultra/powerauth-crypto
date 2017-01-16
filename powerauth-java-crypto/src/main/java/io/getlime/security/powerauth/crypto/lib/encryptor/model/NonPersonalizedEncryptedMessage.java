package io.getlime.security.powerauth.crypto.lib.encryptor.model;

/**
 * Class representing a non-personalized E2EE encrypted message.
 *
 * @author Petr Dvorak, petr@lime-company.eu
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
