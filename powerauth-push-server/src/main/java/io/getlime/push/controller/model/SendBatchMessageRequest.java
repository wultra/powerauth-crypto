package io.getlime.push.controller.model;

import io.getlime.push.controller.model.entity.PushMessage;

import java.util.List;

/**
 * Class representing a request for batch of push messages.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class SendBatchMessageRequest {

    private Long appId;
    private List<PushMessage> batch;

    /**
     * Get app ID.
     * @return App ID.
     */
    public Long getAppId() {
        return appId;
    }

    /**
     * Set app ID.
     * @param appId App ID.
     */
    public void setAppId(Long appId) {
        this.appId = appId;
    }

    /**
     * Get batch list with push notifications to be sent.
     * @param batch Push notification batch.
     */
    public void setBatch(List<PushMessage> batch) {
        this.batch = batch;
    }

    /**
     * Set batch list with push notifications to be sent.
     * @return Push notification batch.
     */
    public List<PushMessage> getBatch() {
        return batch;
    }
}
