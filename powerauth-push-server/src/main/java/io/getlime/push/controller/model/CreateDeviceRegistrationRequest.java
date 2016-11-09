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

    /**
     * Get app ID associated with given device registration.
     * @return App ID.
     */
    public Long getAppId() {
        return appId;
    }

    /**
     * Set app ID associated with given device registration.
     * @param appId App ID.
     */
    public void setAppId(Long appId) {
        this.appId = appId;
    }

    /**
     * Get APNs / FCM push token.
     * @return Push token value.
     */
    public String getToken() {
        return token;
    }

    /**
     * Set APNs / FCM push token.
     * @param token Push token value.
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Get the platform name, either "ios" or "android".
     * @return Platform name, "ios" or "android".
     */
    public String getPlatform() {
        return platform;
    }

    /**
     * Set the platform name.
     * @param platform Platform name.
     */
    public void setPlatform(String platform) {
        this.platform = platform;
    }

    /**
     * Get PowerAuth 2.0 activation ID associated with given device registration.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set PowerAuth 2.0 activation ID associated with given device registration.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

}
