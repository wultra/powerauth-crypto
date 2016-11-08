package io.getlime.push.service.fcm;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Class representing a FCM send message request.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FcmSendRequest {

    private String to;

    @JsonProperty(value = "collapse_key")
    private String collapseKey;

    private Map<String, Object> data;

    private FcmNotification notification;

    public String getTo() {
        return to;
    }

    public void setTo(String to) {
        this.to = to;
    }

    public String getCollapseKey() {
        return collapseKey;
    }

    public void setCollapseKey(String collapseKey) {
        this.collapseKey = collapseKey;
    }

    public Map<String, Object> getData() {
        return data;
    }

    public void setData(Map<String, Object> data) {
        this.data = data;
    }

    public FcmNotification getNotification() {
        return notification;
    }

    public void setNotification(FcmNotification notification) {
        this.notification = notification;
    }
}
