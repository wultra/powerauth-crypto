package io.getlime.push.controller.model;

/**
 * Request object used for device registration.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class CreateDeviceRegistrationRequest {

    private Long appId;
    private String token;
    private String platform;
    private String activationId;

    public Long getAppId() {
        return appId;
    }

    public void setAppId(Long appId) {
        this.appId = appId;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = platform;
    }

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }
}
