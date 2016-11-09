package io.getlime.push.controller.model;

import io.getlime.push.controller.model.entity.PushMessage;

/**
 * Class representing a single push message send request.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class SendPushMessageRequest {

    private Long appId;
    private PushMessage push;

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
     * Get push message to be sent.
     * @return Push message.
     */
    public PushMessage getPush() {
        return push;
    }

    /**
     * Set push message to be sent.
     * @param push Push message.
     */
    public void setPush(PushMessage push) {
        this.push = push;
    }
}
