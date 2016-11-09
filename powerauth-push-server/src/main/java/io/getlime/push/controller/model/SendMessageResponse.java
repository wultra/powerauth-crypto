package io.getlime.push.controller.model;

import io.getlime.push.controller.model.entity.PushSendResult;

/**
 * Class representing a push message sending response.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class SendMessageResponse extends StatusResponse {

    private PushSendResult result;

    public PushSendResult getResult() {
        return result;
    }

    public void setResult(PushSendResult result) {
        this.result = result;
    }

}
