package io.getlime.push.controller.model;

/**
 * Class representing base error response.
 */
public class ErrorResponse extends StatusResponse {

    private String message;

    /**
     * Default constructor, sets `StatusResponse.ERROR` as a status value.
     */
    public ErrorResponse() {
        this.setStatus(StatusResponse.ERROR);
    }

    /**
     * Get error message.
     * @return Error message.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Set error message.
     * @param message Error message.
     */
    public void setMessage(String message) {
        this.message = message;
    }
}
