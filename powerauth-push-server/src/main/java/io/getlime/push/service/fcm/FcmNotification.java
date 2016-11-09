package io.getlime.push.service.fcm;

/**
 * Class representing the FCM notification payload.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class FcmNotification {

    private String title;
    private String body;
    private String sound;
    private String tag;

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

    public String getSound() {
        return sound;
    }

    public void setSound(String sound) {
        this.sound = sound;
    }

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }
}
