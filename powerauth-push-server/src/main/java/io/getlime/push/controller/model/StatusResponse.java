package io.getlime.push.controller.model;

/**
 * Response object with the status indication.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class StatusResponse {

    /**
     * Response is OK.
     */
    public static final String OK = "OK";

    /**
     * Response ended with error state.
     */
    public static final String ERROR = "ERROR";

    private String status;

    /**
     * Get response status, either `StatusResponse.OK` or `StatusResponse.ERROR`.
     * @return Status.
     */
    public String getStatus() {
        return status;
    }

    /**
     * Set status.
     * @param status Status.
     */
    public void setStatus(String status) {
        this.status = status;
    }
}
