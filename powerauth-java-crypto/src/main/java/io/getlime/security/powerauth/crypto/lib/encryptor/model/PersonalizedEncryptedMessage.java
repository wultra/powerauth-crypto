package io.getlime.security.powerauth.crypto.lib.encryptor.model;

/**
 * Class representing a personalized E2EE encrypted message.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PersonalizedEncryptedMessage extends EncryptedMessage {

    private String activationId;

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

}
