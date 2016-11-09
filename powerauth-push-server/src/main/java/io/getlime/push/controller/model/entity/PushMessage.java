package io.getlime.push.controller.model.entity;

/**
 * Class representing a single push message model.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PushMessage {

    private String userId;
    private String activationId;
    private Boolean silent = false;
    private Boolean personal = false;
    private Boolean encrypted = false;
    private PushMessageBody message;

    /**
     * Get user ID.
     * @return User ID.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set user ID.
     * @param userId User ID.
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get PowerAuth 2.0 activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set PowerAuth 2.0 activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Specifies if the message should be silent - it does not play any sound and trigger any displayable message.
     * Default value if false.
     * @return True if the message should be silent, false otherwise.  Default value if false.
     */
    public Boolean getSilent() {
        return silent;
    }

    /**
     * Set if the message should be silent - it does not play any sound and trigger any displayable message.
     * Default value if false.
     * @param silent True if the message should be silent, false otherwise. Default value if false.
     */
    public void setSilent(Boolean silent) {
        this.silent = silent;
    }

    /**
     * Specifies if the message is personal. Personal messages are delivered to provided recipient only in case
     * associated PowerAuth 2.0 activations are in active state. They are not delivered in case of any other
     * activation states. Default value if false.
     * @return True if the message is personal, false otherwise. Default value if false.
     */
    public Boolean getPersonal() {
        return personal;
    }

    /**
     * Set if the message is personal. Personal messages are delivered to provided recipient only in case
     * associated PowerAuth 2.0 activations are in active state. They are not delivered in case of any other
     * activation states.  Default value if false.
     * @return True if the message is personal, false otherwise.  Default value if false.
     */
    public void setPersonal(Boolean personal) {
        this.personal = personal;
    }

    /**
     * Specifies if the message data payload ('extras') should be encrypted using PowerAuth 2.0 end-to-end
     * encryption. Default value if false.
     * @return True if the message should be encrypted, false otherwise. Default value if false.
     */
    public Boolean getEncrypted() {
        return encrypted;
    }

    /**
     * Sets if the message data payload ('extras') should be encrypted using PowerAuth 2.0 end-to-end
     * encryption. Default value if false.
     * @param encrypted True if the message should be encrypted, false otherwise. Default value if false.
     */
    public void setEncrypted(Boolean encrypted) {
        this.encrypted = encrypted;
    }

    /**
     * Get the push message contents.
     * @return Push message contents.
     */
    public PushMessageBody getMessage() {
        return message;
    }

    /**
     * Set the push message contents.
     * @param message Push message contents.
     */
    public void setMessage(PushMessageBody message) {
        this.message = message;
    }
}
