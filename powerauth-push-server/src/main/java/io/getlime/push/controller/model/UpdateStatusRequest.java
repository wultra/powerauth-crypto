package io.getlime.push.controller.model;

/**
 * Class representing request object responsible for updating activation status.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class UpdateStatusRequest {

    private String activationId;
    private String status;

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
