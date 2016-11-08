package io.getlime.push.controller.model;

import io.getlime.push.controller.model.entity.PushMessage;

import java.util.List;

/**
 * Class representing a request for batch of push messages.
 */
public class SendBatchMessageRequest {

    private Long appId;
    private List<PushMessage> batch;

    public Long getAppId() {
        return appId;
    }

    public void setAppId(Long appId) {
        this.appId = appId;
    }

    public void setBatch(List<PushMessage> batch) {
        this.batch = batch;
    }

    public List<PushMessage> getBatch() {
        return batch;
    }
}
