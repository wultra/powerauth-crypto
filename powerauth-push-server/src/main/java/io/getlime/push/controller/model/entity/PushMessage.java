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

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    public Boolean getSilent() {
        return silent;
    }

    public void setSilent(Boolean silent) {
        this.silent = silent;
    }

    public Boolean getPersonal() {
        return personal;
    }

    public void setPersonal(Boolean personal) {
        this.personal = personal;
    }

    public Boolean getEncrypted() {
        return encrypted;
    }

    public void setEncrypted(Boolean encrypted) {
        this.encrypted = encrypted;
    }

    public PushMessageBody getMessage() {
        return message;
    }

    public void setMessage(PushMessageBody message) {
        this.message = message;
    }
}
