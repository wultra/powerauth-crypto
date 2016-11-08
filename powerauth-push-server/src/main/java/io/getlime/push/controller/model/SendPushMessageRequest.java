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

    public Long getAppId() {
        return appId;
    }

    public void setAppId(Long appId) {
        this.appId = appId;
    }

    public PushMessage getPush() {
        return push;
    }

    public void setPush(PushMessage push) {
        this.push = push;
    }
}
