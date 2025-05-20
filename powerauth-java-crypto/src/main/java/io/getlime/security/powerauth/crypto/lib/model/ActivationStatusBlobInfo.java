/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.model;

/**
 * Information about activation status as parsed from the blob provided by
 * calling /pa/activation/status end-point.
 *
 * @author Petr Dvorak
 *
 */
public class ActivationStatusBlobInfo {

    /**
     * Activation status magic value.
     */
    public static final int ACTIVATION_STATUS_MAGIC_VALUE = 0xDEC0DED1;

    private boolean valid;
    private byte activationStatus;
    private byte currentVersion;
    private byte upgradeVersion;
    private byte failedAttempts;
    private byte maxFailedAttempts;
    private byte ctrLookAhead;
    private byte ctrByte;
    private byte[] ctrDataHash;

    /**
     * Return true in case the parsed data was valid (correctly decrypted using transport key), false otherwise.
     * @return True in case the parsed data was valid (correctly decrypted using transport key), false otherwise.
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Set validity state. Set this value to true in case status blob was correctly decrypted, set to false
     * otherwise.
     * @param valid True in case decryption was successful, false otherwise.
     */
    public void setValid(boolean valid) {
        this.valid = valid;
    }

    /**
     * Get activation status.
     * @return Activation status.
     */
    public byte getActivationStatus() {
        return activationStatus;
    }

    /**
     * Set activation status.
     * @param activationStatus Activation status.
     */
    public void setActivationStatus(byte activationStatus) {
        this.activationStatus = activationStatus;
    }

    /**
     * Get current crypto protocol version.
     * @return Current crypto protocol version.
     */
    public byte getCurrentVersion() {
        return currentVersion;
    }

    /**
     * Set current crypto protocol version.
     * @param currentVersion Current crypto protocol version.
     */
    public void setCurrentVersion(byte currentVersion) {
        this.currentVersion = currentVersion;
    }

    /**
     * Get crypto version for possible upgrade.
     * @return Crypto version for possible upgrade.
     */
    public byte getUpgradeVersion() {
        return upgradeVersion;
    }

    /**
     * Set crypto version for possible upgrade.
     * @param upgradeVersion Crypto version for possible upgrade.
     */
    public void setUpgradeVersion(byte upgradeVersion) {
        this.upgradeVersion = upgradeVersion;
    }

    /**
     * Get failed attempt amount.
     * @return Number of failed attempts.
     */
    public byte getFailedAttempts() {
        return failedAttempts;
    }

    /**
     * Set failed attempt amount.
     * @param failedAttempts Number of failed attempts.
     */
    public void setFailedAttempts(byte failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    /**
     * Get maximum allowed failed attempt count.
     * @return Maximum allowed failed attempt count.
     */
    public byte getMaxFailedAttempts() {
        return maxFailedAttempts;
    }

    /**
     * Set maximum allowed failed attempt count.
     * @param maxFailedAttempts Maximum allowed failed attempt count.
     */
    public void setMaxFailedAttempts(byte maxFailedAttempts) {
        this.maxFailedAttempts = maxFailedAttempts;
    }

    /**
     * Get value for counter's look ahead window.
     * @return Counter's look ahead window value.
     */
    public byte getCtrLookAhead() {
        return ctrLookAhead;
    }

    /**
     * Set counter's look ahead window.
     * @param ctrLookAhead Look ahead window.
     */
    public void setCtrLookAhead(byte ctrLookAhead) {
        this.ctrLookAhead = ctrLookAhead;
    }

    /**
     * Get least significant byte from the counter.
     * @return Least significant byte from the counter.
     */
    public byte getCtrByte() {
        return ctrByte;
    }

    /**
     * Set least significant byte from the counter.
     * @param ctrByte Least significant byte from the counter.
     */
    public void setCtrByte(byte ctrByte) {
        this.ctrByte = ctrByte;
    }

    /**
     * Get counter data hash.
     * @return Counter data hash.
     */
    public byte[] getCtrDataHash() {
        return ctrDataHash;
    }

    /**
     * Set counter data hash.
     * @param ctrDataHash Counter data.
     */
    public void setCtrDataHash(byte[] ctrDataHash) {
        this.ctrDataHash = ctrDataHash;
    }
}
