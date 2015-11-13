package io.getlime.security.service.controller;

/**
 * Class representing an error returned by RESTful API
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
public class RESTErrorModel {

    private String code;
    private String message;
    private String localizedMessage;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getLocalizedMessage() {
        return localizedMessage;
    }

    public void setLocalizedMessage(String localizedMessage) {
        this.localizedMessage = localizedMessage;
    }

}
