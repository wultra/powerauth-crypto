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

    /**
     * Push message title. Short and digestible message stating the message purpose, for example "Balance update".
     * @return Push message title.
     */
    public String getTitle() {
        return title;
    }

    /**
     * Set push message title. Short and digestible message stating the message purpose, for
     * example "Balance update".
     * @param title Push message title.
     */
    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * Get long message text, used as a notification body. Place your message to this property,
     * for example "Your today's balance is $782.40".
     * @return Notification body text.
     */
    public String getBody() {
        return body;
    }

    /**
     * Set long message text, used as a notification body. Place your message to this property,
     * for example "Your today's balance is $782.40".
     * @param body Notification body text.
     */
    public void setBody(String body) {
        this.body = body;
    }

    /**
     * App icon badge value (iOS only).
     * @return App icon badge.
     */
    public Integer getBadge() {
        return badge;
    }

    /**
     * Set app icon badge value (iOS only).
     * @param badge App icon badge.
     */
    public void setBadge(Integer badge) {
        this.badge = badge;
    }

    /**
     * Get the sound name to be played with the notification.
     * @return Sound name.
     */
    public String getSound() {
        return sound;
    }

    /**
     * Set the sound name to be played with the notification.
     * @param sound Sound name.
     */
    public void setSound(String sound) {
        this.sound = sound;
    }

    /**
     * Get the notification category, used to distinguish actions assinged with the notification.
     * @return Notification category.
     */
    public String getCategory() {
        return category;
    }

    /**
     * Set the notification category, used to distinguish actions assinged with the notification.
     * @param category Notification category.
     */
    public void setCategory(String category) {
        this.category = category;
    }

    /**
     * Get the collapse key, used to collapse messages on the server in case messages cannot be delivered and
     * as a tag / thread ID to group messages with the same content type.
     * @return Notification collapse key.
     */
    public String getCollapseKey() {
        return collapseKey;
    }

    /**
     * Set the collapse key, used to collapse messages on the server in case messages cannot be delivered and
     * as a tag / thread ID to group messages with the same content type.
     * @param collapseKey Notification collapse key.
     */
    public void setCollapseKey(String collapseKey) {
        this.collapseKey = collapseKey;
    }

    /**
     * Get notification delivery validity (timestamp message should live to in case it's not delivered immediately).
     * @return Validity timestamp.
     */
    public Date getValidUntil() {
        return validUntil;
    }

    /**
     * Set notification delivery validity (timestamp message should live to in case it's not delivered immediately).
     * @param validUntil Validity timestamp.
     */
    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

    /**
     * Get the map (Map&lt;String, Object&gt;) with optional message parameters. This is translated to custom parameters
     * on iOS and to data notification payload object on Android.
     * @return Extra attributes.
     */
    public Map<String, Object> getExtras() {
        return extras;
    }

    /**
     * Set the map (Map&lt;String, Object&gt;) with optional message parameters. This is translated to custom parameters
     * on iOS and to data notification payload object on Android.
     * @param extras Extra attributes.
     */
    public void setExtras(Map<String, Object> extras) {
        this.extras = extras;
    }
}
