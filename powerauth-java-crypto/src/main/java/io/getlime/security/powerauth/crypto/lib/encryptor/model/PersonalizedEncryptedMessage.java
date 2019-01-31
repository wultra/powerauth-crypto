package io.getlime.security.powerauth.crypto.lib.encryptor.model;

/**
 * Class representing a personalized E2EE encrypted message.
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
public class PersonalizedEncryptedMessage extends EncryptedMessage {

    private String activationId;

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

}
