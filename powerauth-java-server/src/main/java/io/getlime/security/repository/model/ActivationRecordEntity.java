package io.getlime.security.repository.model;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

@Entity(name = "pa_activation")
public class ActivationRecordEntity implements Serializable {

    @Id
    @Column(length = 37)
    private String activationId;

    @Column(nullable = false, updatable = false)
    private String activationIdShort;

    @Column(nullable = false, updatable = false)
    private String activationOTP;

    @Column(nullable = false, updatable = false)
    private String userId;

    @Column(nullable = true)
    private String clientName;

    @Column(nullable = false)
    private byte[] serverPrivateKey;

    @Column(nullable = false)
    private byte[] serverPublicKey;

    @Column(nullable = true)
    private byte[] devicePublicKey;

    @Column(nullable = false)
    private Long counter;

    @Column
    private Long failedAttempts;

    @Column(nullable = false)
    private Long timestampCreated;

    @Column(nullable = false)
    private Long timestampLastUsed;

    @Column(nullable = false)
    private ActivationStatus activationStatus;

    @ManyToOne
    @JoinColumn(referencedColumnName = "id", nullable = false)
    private MasterKeyPairEntity masterKeypair;

    protected ActivationRecordEntity() {
    }

    public ActivationRecordEntity(
            String activationId,
            String activationIdShort,
            String activationOTP,
            String userId,
            String clientName,
            byte[] serverPrivateKey,
            byte[] serverPublicKey,
            byte[] devicePublicKey,
            Long counter,
            Long failedAttempts,
            Long timestampCreated,
            Long timestampLastUsed,
            ActivationStatus status,
            MasterKeyPairEntity masterKeypair) {
        this.activationId = activationId;
        this.activationIdShort = activationIdShort;
        this.activationOTP = activationOTP;
        this.userId = userId;
        this.clientName = clientName;
        this.serverPrivateKey = serverPrivateKey;
        this.serverPublicKey = serverPublicKey;
        this.devicePublicKey = devicePublicKey;
        this.counter = counter;
        this.failedAttempts = failedAttempts;
        this.timestampCreated = timestampCreated;
        this.timestampLastUsed = timestampLastUsed;
        this.activationStatus = status;
        this.masterKeypair = masterKeypair;
    }

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    public String getActivationIdShort() {
        return activationIdShort;
    }

    public void setActivationIdShort(String activationIdShort) {
        this.activationIdShort = activationIdShort;
    }

    public String getActivationOTP() {
        return activationOTP;
    }

    public void setActivationOTP(String activationOTP) {
        this.activationOTP = activationOTP;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public byte[] getServerPrivateKey() {
        return serverPrivateKey;
    }

    public void setServerPrivateKey(byte[] serverPrivateKey) {
        this.serverPrivateKey = serverPrivateKey;
    }

    public byte[] getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(byte[] serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public byte[] getDevicePublicKey() {
        return devicePublicKey;
    }

    public void setDevicePublicKey(byte[] devicePublicKey) {
        this.devicePublicKey = devicePublicKey;
    }

    public Long getCounter() {
        return counter;
    }

    public void setCounter(Long counter) {
        this.counter = counter;
    }

    public Long getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(Long failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public Long getTimestampCreated() {
        return timestampCreated;
    }

    public void setTimestampCreated(Long timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    public Long getTimestampLastUsed() {
        return timestampLastUsed;
    }

    public void setTimestampLastUsed(Long timestampLastUsed) {
        this.timestampLastUsed = timestampLastUsed;
    }

    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    public MasterKeyPairEntity getMasterKeypair() {
        return masterKeypair;
    }

    public void setMasterKeypair(MasterKeyPairEntity masterKeypair) {
        this.masterKeypair = masterKeypair;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Objects.hashCode(this.activationId);
        hash = 71 * hash + Objects.hashCode(this.activationIdShort);
        hash = 71 * hash + Objects.hashCode(this.activationOTP);
        hash = 71 * hash + Objects.hashCode(this.userId);
        hash = 71 * hash + Objects.hashCode(this.clientName);
        hash = 71 * hash + Arrays.hashCode(this.serverPrivateKey);
        hash = 71 * hash + Arrays.hashCode(this.serverPublicKey);
        hash = 71 * hash + Arrays.hashCode(this.devicePublicKey);
        hash = 71 * hash + Objects.hashCode(this.counter);
        hash = 71 * hash + Objects.hashCode(this.failedAttempts);
        hash = 71 * hash + Objects.hashCode(this.timestampCreated);
        hash = 71 * hash + Objects.hashCode(this.timestampLastUsed);
        hash = 71 * hash + Objects.hashCode(this.activationStatus);
        hash = 71 * hash + Objects.hashCode(this.masterKeypair);
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
        if (!Objects.equals(this.clientName, other.clientName)) {
            return false;
        }
        if (!Objects.equals(this.activationId, other.activationId)) {
            return false;
        }
        if (!Arrays.equals(this.serverPrivateKey, other.serverPrivateKey)) {
            return false;
        }
        if (!Arrays.equals(this.serverPublicKey, other.serverPublicKey)) {
            return false;
        }
        if (!Arrays.equals(this.devicePublicKey, other.devicePublicKey)) {
            return false;
        }
        if (!Objects.equals(this.counter, other.counter)) {
            return false;
        }
        if (!Objects.equals(this.failedAttempts, other.failedAttempts)) {
            return false;
        }
        if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
            return false;
        }
        if (!Objects.equals(this.timestampLastUsed, other.timestampLastUsed)) {
            return false;
        }
        if (this.activationStatus != other.activationStatus) {
            return false;
        }
        if (!Objects.equals(this.masterKeypair, other.masterKeypair)) {
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
                + ", clientName=" + clientName
                + ", serverPrivateKey=" + Arrays.toString(serverPrivateKey)
                + ", serverPublicKey=" + Arrays.toString(serverPublicKey)
                + ", devicePublicKey=" + Arrays.toString(devicePublicKey)
                + ", counter=" + counter
                + ", failedAttempts=" + failedAttempts
                + ", timestampCreated=" + timestampCreated
                + ", timestampLastUsed=" + timestampLastUsed
                + ", status=" + activationStatus
                + ", masterKeypair=" + masterKeypair
                + '}';
    }

}
