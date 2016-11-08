package io.getlime.push.controller.model;

import io.getlime.push.controller.model.entity.PushSendResult;

/**
 * Created by petrdvorak on 06/11/2016.
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
