package io.getlime.push.controller.model;

/**
 * Class representing request object responsible for device registration removal.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class RemoveDeviceRegistrationRequest {

    private Long appId;
    private String token;

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
}
