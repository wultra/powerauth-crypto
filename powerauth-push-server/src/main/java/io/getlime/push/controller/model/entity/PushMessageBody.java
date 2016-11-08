package io.getlime.push.controller.model.entity;

import org.joda.time.DateTime;

import java.util.Date;
import java.util.Map;

/**
 * Class representing a message body - the information that do not serve as a "message descriptor"
 * but rather as payload. This data package is a subject of end-to-end encryption.
 */
public class PushMessageBody {

    private String title;
    private String body;
    private Integer badge;
    private String sound;
    private String category;
    private String collapseKey;
    private Date validUntil;
    private Map<String, Object> extras;

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public Integer getBadge() {
        return badge;
    }

    public void setBadge(Integer badge) {
        this.badge = badge;
    }

    public String getSound() {
        return sound;
    }

    public void setSound(String sound) {
        this.sound = sound;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getCollapseKey() {
        return collapseKey;
    }

    public void setCollapseKey(String collapseKey) {
        this.collapseKey = collapseKey;
    }

    public Date getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

    public Map<String, Object> getExtras() {
        return extras;
    }

    public void setExtras(Map<String, Object> extras) {
        this.extras = extras;
    }
}
