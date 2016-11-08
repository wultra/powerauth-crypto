package io.getlime.push.controller.model;

/**
 * Created by petrdvorak on 08/11/2016.
 */
public class ErrorResponse extends StatusResponse {



    public ErrorResponse() {
        this.setStatus(StatusResponse.ERROR);
    }
}
