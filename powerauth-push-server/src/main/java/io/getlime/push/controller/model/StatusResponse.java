package io.getlime.push.controller.model;

/**
 * Response object with the status indication.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class StatusResponse {

    public static final String OK = "OK";
    public static final String ERROR = "ERROR";

    private String status;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
