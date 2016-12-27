/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.security.powerauth.app.server.repository.model.entity;

import io.getlime.security.powerauth.app.server.repository.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.repository.model.ActivationStatusConverter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Database entity for an "activation" objects.
 *
 * @author Petr Dvorak
 */
@Entity(name = "pa_activation")
public class ActivationRecordEntity implements Serializable {

    private static final long serialVersionUID = 7512286634644851705L;

    @Id
    @Column(name = "activation_id", length = 37)
    private String activationId;

    @Column(name = "activation_id_short", nullable = false, updatable = false)
    private String activationIdShort;

    @Column(name = "activation_otp", nullable = false, updatable = false)
    private String activationOTP;

    @Column(name = "user_id", nullable = false, updatable = false)
    private String userId;

    @Column(name = "activation_name", nullable = true)
    private String activationName;

    @Column(name = "extras", nullable = true)
    private String extras;

    @Column(name = "server_private_key_base64", nullable = false)
    private String serverPrivateKeyBase64;

    @Column(name = "server_public_key_base64", nullable = false)
    private String serverPublicKeyBase64;

    @Column(name = "device_public_key_base64", nullable = true)
    private String devicePublicKeyBase64;

    @Column(name = "counter", nullable = false)
    private Long counter;

    @Column(name = "failed_attempts", nullable = false)
    private Long failedAttempts;

    @Column(name = "max_failed_attempts", nullable = false)
    private Long maxFailedAttempts;

    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    @Column(name = "timestamp_activation_expire", nullable = false)
    private Date timestampActivationExpire;

    @Column(name = "timestamp_last_used", nullable = false)
    private Date timestampLastUsed;

    @Column(name = "activation_status", nullable = false)
    @Convert(converter = ActivationStatusConverter.class)
    private ActivationStatus activationStatus;

    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false)
    private ApplicationEntity application;

    @ManyToOne
    @JoinColumn(name = "master_keypair_id", referencedColumnName = "id", nullable = false)
    private MasterKeyPairEntity masterKeyPair;

    /**
     * Default constructor.
     */
    public ActivationRecordEntity() {
    }

    /**
     * Constructor with all parameters.
     *
     * @param activationId              Activation ID
     * @param activationIdShort         Activation Id Short
     * @param activationOTP             Activation OTP
     * @param userId                    User Id
     * @param activationName            Activation name
     * @param extras                    Extra parameter
     * @param serverPrivateKeyBase64    Server private key encoded as Base64
     * @param serverPublicKeyBase64     Server public key encoded as Base64.
     * @param devicePublicKeyBase64     device public key encoded as Base64.
     * @param counter                   Counter
     * @param failedAttempts            Current failed attempt count.
     * @param maxFailedAttempts         Maximum allowed failed attempt count.
     * @param timestampCreated          Created timestamp.
     * @param timestampActivationExpire Activation completion expiration timestamp.
     * @param timestampLastUsed         Last signature timestamp.
     * @param activationStatus          Activation status.
     * @param masterKeyPair             Associated master keypair.
     * @param application               Associated application.
     */
    public ActivationRecordEntity(String activationId,
                                  String activationIdShort,
                                  String activationOTP,
                                  String userId,
                                  String activationName,
                                  String extras,
                                  String serverPrivateKeyBase64,
                                  String serverPublicKeyBase64,
                                  String devicePublicKeyBase64,
                                  Long counter,
                                  Long failedAttempts,
                                  Long maxFailedAttempts,
                                  Date timestampCreated,
                                  Date timestampActivationExpire,
                                  Date timestampLastUsed,
                                  ActivationStatus activationStatus,
                                  MasterKeyPairEntity masterKeyPair,
                                  ApplicationEntity application) {
        super();
        this.activationId = activationId;
        this.activationIdShort = activationIdShort;
        this.activationOTP = activationOTP;
        this.userId = userId;
        this.activationName = activationName;
        this.extras = extras;
        this.serverPrivateKeyBase64 = serverPrivateKeyBase64;
        this.serverPublicKeyBase64 = serverPublicKeyBase64;
        this.devicePublicKeyBase64 = devicePublicKeyBase64;
        this.counter = counter;
        this.failedAttempts = failedAttempts;
        this.maxFailedAttempts = maxFailedAttempts;
        this.timestampCreated = timestampCreated;
        this.timestampActivationExpire = timestampActivationExpire;
        this.timestampLastUsed = timestampLastUsed;
        this.activationStatus = activationStatus;
        this.masterKeyPair = masterKeyPair;
        this.application = application;
    }

    /**
     * Get activation ID.
     *
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     *
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get short activation ID
     *
     * @return Short activation ID
     */
    public String getActivationIdShort() {
        return activationIdShort;
    }

    /**
     * Set short activation ID
     *
     * @param activationIdShort Short activation ID
     */
    public void setActivationIdShort(String activationIdShort) {
        this.activationIdShort = activationIdShort;
    }

    /**
     * Get activation OTP
     *
     * @return Activation OTP
     */
    public String getActivationOTP() {
        return activationOTP;
    }

    /**
     * Set activation OTP
     *
     * @param activationOTP Activation OTP
     */
    public void setActivationOTP(String activationOTP) {
        this.activationOTP = activationOTP;
    }

    /**
     * Get user ID
     *
     * @return User ID
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set user ID
     *
     * @param userId User ID
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get activation name
     *
     * @return Activation name
     */
    public String getActivationName() {
        return activationName;
    }

    /**
     * Set activation name
     *
     * @param activationName Activation name
     */
    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    /**
     * Get extra parameter
     *
     * @return Extra parameter
     */
    public String getExtras() {
        return extras;
    }

    /**
     * Set extra parameter
     *
     * @param extras Extra parameter
     */
    public void setExtras(String extras) {
        this.extras = extras;
    }

    /**
     * Get Base64 encoded server private key
     *
     * @return Base64 encoded server private key
     */
    public String getServerPrivateKeyBase64() {
        return serverPrivateKeyBase64;
    }

    /**
     * Set Base64 encoded server private key.
     *
     * @param serverPrivateKeyBase64 Base64 encoded server private key.
     */
    public void setServerPrivateKeyBase64(String serverPrivateKeyBase64) {
        this.serverPrivateKeyBase64 = serverPrivateKeyBase64;
    }

    /**
     * Get Base64 encoded server public key
     *
     * @return Base64 encoded server public key
     */
    public String getServerPublicKeyBase64() {
        return serverPublicKeyBase64;
    }

    /**
     * Set Base64 encoded server public key
     *
     * @param serverPublicKeyBase64 Base64 encoded server public key
     */
    public void setServerPublicKeyBase64(String serverPublicKeyBase64) {
        this.serverPublicKeyBase64 = serverPublicKeyBase64;
    }

    /**
     * Get Base64 encoded device public key
     *
     * @return Base64 encoded device public key
     */
    public String getDevicePublicKeyBase64() {
        return devicePublicKeyBase64;
    }

    /**
     * Set Base64 encoded device public key
     *
     * @param devicePublicKeyBase64 Base64 encoded device public key
     */
    public void setDevicePublicKeyBase64(String devicePublicKeyBase64) {
        this.devicePublicKeyBase64 = devicePublicKeyBase64;
    }

    /**
     * Get counter value
     *
     * @return Counter
     */
    public Long getCounter() {
        return counter;
    }

    /**
     * Set counter value
     *
     * @param counter Counter
     */
    public void setCounter(Long counter) {
        this.counter = counter;
    }

    /**
     * Get current number of failed attempts
     *
     * @return Failed attempts
     */
    public Long getFailedAttempts() {
        return failedAttempts;
    }

    /**
     * Set current number of failed attempts
     *
     * @param failedAttempts Failed attempts
     */
    public void setFailedAttempts(Long failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    /**
     * Get maximum allowed number of failed attempts
     *
     * @return Max. amount of allowed failed attempts
     */
    public Long getMaxFailedAttempts() {
        return maxFailedAttempts;
    }

    /**
     * Set maximum allowed number of failed attempts
     *
     * @param maxFailedAttempts Max. amount of allowed failed attempts
     */
    public void setMaxFailedAttempts(Long maxFailedAttempts) {
        this.maxFailedAttempts = maxFailedAttempts;
    }

    /**
     * Get created timestamp
     *
     * @return Created timestamp
     */
    public Date getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set created timestamp
     *
     * @param timestampCreated Created timestamp
     */
    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get timestamp of activation completion expiration - application must turn
     * from CREATED to ACTIVE state before this moment, or else it will turn REMOVED
     * on next access.
     *
     * @return Timestamp of activation completion expiration.
     */
    public Date getTimestampActivationExpire() {
        return timestampActivationExpire;
    }

    /**
     * Set timestamp of activation completion expiration - application must turn
     * from CREATED to ACTIVE state before this moment, or else it will turn REMOVED
     * on next access.
     *
     * @param timestampActivationExpire Timestamp of activation completion expiration.
     */
    public void setTimestampActivationExpire(Date timestampActivationExpire) {
        this.timestampActivationExpire = timestampActivationExpire;
    }

    /**
     * Get timestamp of the last signature calculation
     *
     * @return Timestamp of the last signature calculation
     */
    public Date getTimestampLastUsed() {
        return timestampLastUsed;
    }

    /**
     * Set timestamp of the last signature calculation
     *
     * @param timestampLastUsed timestamp of the last signature calculation
     */
    public void setTimestampLastUsed(Date timestampLastUsed) {
        this.timestampLastUsed = timestampLastUsed;
    }

    /**
     * Get activation status.
     *
     * @return Activation status, value of {@link ActivationStatus}
     */
    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    /**
     * Set activation status.
     *
     * @param activationStatus Activation status, value of {@link ActivationStatus}
     */
    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    /**
     * Get associated application instance. Each activation is strongly associated with
     * a single application.
     *
     * @return Associated application, instance of {@link ApplicationEntity}
     */
    public ApplicationEntity getApplication() {
        return application;
    }

    /**
     * Set associated application instance. Each activation is strongly associated with
     * a single application.
     *
     * @param application Associated application, instance of {@link ApplicationEntity}
     */
    public void setApplication(ApplicationEntity application) {
        this.application = application;
    }

    /**
     * Get associated master key pair. While master key pair is associated with an application
     * by default, it must also be associated with an activation when a new activation is
     * created so that it is strongly bound with the activation.
     *
     * @return Master Key Pair.
     */
    public MasterKeyPairEntity getMasterKeyPair() {
        return masterKeyPair;
    }

    /**
     * Set associated master key pair. While master key pair is associated with an application
     * by default, it must also be associated with an activation when a new activation is
     * created so that it is strongly bound with the activation.
     *
     * @param masterKeyPair Master Key Pair.
     */
    public void setMasterKeyPair(MasterKeyPairEntity masterKeyPair) {
        this.masterKeyPair = masterKeyPair;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Objects.hashCode(this.activationId);
        hash = 71 * hash + Objects.hashCode(this.activationIdShort);
        hash = 71 * hash + Objects.hashCode(this.activationOTP);
        hash = 71 * hash + Objects.hashCode(this.userId);
        hash = 71 * hash + Objects.hashCode(this.activationName);
        hash = 71 * hash + Objects.hashCode(this.serverPrivateKeyBase64);
        hash = 71 * hash + Objects.hashCode(this.serverPublicKeyBase64);
        hash = 71 * hash + Objects.hashCode(this.devicePublicKeyBase64);
        hash = 71 * hash + Objects.hashCode(this.counter);
        hash = 71 * hash + Objects.hashCode(this.failedAttempts);
        hash = 71 * hash + Objects.hashCode(this.maxFailedAttempts);
        hash = 71 * hash + Objects.hashCode(this.timestampCreated);
        hash = 71 * hash + Objects.hashCode(this.timestampActivationExpire);
        hash = 71 * hash + Objects.hashCode(this.timestampLastUsed);
        hash = 71 * hash + Objects.hashCode(this.activationStatus);
        hash = 71 * hash + Objects.hashCode(this.application);
        hash = 71 * hash + Objects.hashCode(this.masterKeyPair);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ActivationRecordEntity other = (ActivationRecordEntity) obj;
        if (!Objects.equals(this.activationIdShort, other.activationIdShort)) {
            return false;
        }
        if (!Objects.equals(this.activationOTP, other.activationOTP)) {
            return false;
        }
        if (!Objects.equals(this.userId, other.userId)) {
            return false;
        }
        if (!Objects.equals(this.activationName, other.activationName)) {
            return false;
        }
        if (!Objects.equals(this.activationId, other.activationId)) {
            return false;
        }
        if (!Objects.equals(this.serverPrivateKeyBase64, other.serverPrivateKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.serverPublicKeyBase64, other.serverPublicKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.devicePublicKeyBase64, other.devicePublicKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.counter, other.counter)) {
            return false;
        }
        if (!Objects.equals(this.failedAttempts, other.failedAttempts)) {
            return false;
        }
        if (!Objects.equals(this.maxFailedAttempts, other.maxFailedAttempts)) {
            return false;
        }
        if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
            return false;
        }
        if (!Objects.equals(this.timestampActivationExpire, other.timestampActivationExpire)) {
            return false;
        }
        if (!Objects.equals(this.timestampLastUsed, other.timestampLastUsed)) {
            return false;
        }
        if (this.activationStatus != other.activationStatus) {
            return false;
        }
        if (!Objects.equals(this.application, other.application)) {
            return false;
        }
        if (!Objects.equals(this.masterKeyPair, other.masterKeyPair)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "ActivationRecordEntity{"
                + "activationId=" + activationId
                + ", activationIdShort=" + activationIdShort
                + ", activationOTP=" + activationOTP
                + ", userId=" + userId
                + ", clientName=" + activationName
                + ", serverPrivateKeyBase64=" + serverPrivateKeyBase64
                + ", serverPublicKeyBase64=" + serverPublicKeyBase64
                + ", devicePublicKeyBase64=" + devicePublicKeyBase64
                + ", counter=" + counter
                + ", failedAttempts=" + failedAttempts
                + ", maxFailedAttempts=" + maxFailedAttempts
                + ", timestampCreated=" + timestampCreated
                + ", timestampActivationExpire=" + timestampActivationExpire
                + ", timestampLastUsed=" + timestampLastUsed
                + ", status=" + activationStatus
                + ", masterKeyPair=" + masterKeyPair
                + ", application=" + application
                + '}';
    }

}
