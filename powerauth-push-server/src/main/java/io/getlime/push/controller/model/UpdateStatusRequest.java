package io.getlime.push.controller.model;

/**
 * Class representing request object responsible for updating activation status.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class UpdateStatusRequest {

    private String activationId;
    private String status;

    /**
     * Get PowerAuth 2.0 Activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set PowerAuth 2.0 Activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get PowerAuth 2.0 Activation status (CREATED, OTP_USED, ACTIVE, BLOCKED, REMOVED).
     * @return PowerAuth 2.0 Activation status (CREATED, OTP_USED, ACTIVE, BLOCKED, REMOVED).
     */
    public String getStatus() {
        return status;
    }

    /**
     * Set PowerAuth 2.0 Activation status (CREATED, OTP_USED, ACTIVE, BLOCKED, REMOVED).
     * @param status PowerAuth 2.0 Activation status (CREATED, OTP_USED, ACTIVE, BLOCKED, REMOVED).
     */
    public void setStatus(String status) {
        this.status = status;
    }
}
