package io.getlime.push.repository.model;

import org.joda.time.DateTime;

import javax.persistence.*;
import java.io.Serializable;

/**
 * Class representing application tokens used to authenticate against APNs or FCM services.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Entity(name = "push_app_credentials")
public class AppCredentials implements Serializable {

    private static final long serialVersionUID = -8904070389354612019L;

    @Id
    @Column(name = "id")
    @SequenceGenerator(name = "push_app_credentials", sequenceName = "push_app_credentials_sequence")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "push_app_credentials")
    private Long id;

    @Column(name = "app_id", nullable = false, updatable = false)
    private Long appId;

    @Column(name = "ios")
    private byte[] ios;

    @Column(name = "ios_bundle")
    private String iosBundle;

    @Column(name = "ios_password")
    private String iosPassword;

    @Column(name = "android")
    private String android;

    @Column(name = "android_bundle")
    private String androidBundle;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getAppId() {
        return appId;
    }

    public void setAppId(Long appId) {
        this.appId = appId;
    }

    public String getIosBundle() {
        return iosBundle;
    }

    public void setIosBundle(String iosBundle) {
        this.iosBundle = iosBundle;
    }

    public byte[] getIos() {
        return ios;
    }

    public void setIos(byte[] ios) {
        this.ios = ios;
    }

    public String getIosPassword() {
        return iosPassword;
    }

    public void setIosPassword(String iosPassword) {
        this.iosPassword = iosPassword;
    }

    public String getAndroid() {
        return android;
    }

    public void setAndroid(String android) {
        this.android = android;
    }

    public String getAndroidBundle() {
        return androidBundle;
    }

    public void setAndroidBundle(String androidBundle) {
        this.androidBundle = androidBundle;
    }
}
