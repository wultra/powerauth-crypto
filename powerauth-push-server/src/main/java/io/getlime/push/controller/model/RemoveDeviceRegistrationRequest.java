package io.getlime.push.controller.model;

/**
 * Class representing request object responsible for device registration removal.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class RemoveDeviceRegistrationRequest {

    private Long appId;
    private String token;

    /**
     * Get app ID.
     * @return App ID.
     */
    public Long getAppId() {
        return appId;
    }

    /**
     * Set app ID.
     * @param appId App ID.
     */
    public void setAppId(Long appId) {
        this.appId = appId;
    }

    /**
     * Get push token value.
     * @return Push token.
     */
    public String getToken() {
        return token;
    }

    /**
     * Set push token value.
     * @param token Push token.
     */
    public void setToken(String token) {
        this.token = token;
    }
}
