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
package io.getlime.security.powerauth.lib.model;

/**
 * Information about activation status as parsed from the blob provided by
 * calling /pa/activation/status end-point.
 *
 * @author Petr Dvorak
 *
 */
public class ActivationStatusBlobInfo {

    private boolean valid;
    private byte activationStatus;
    private long counter;
    private byte failedAttempts;
    private byte maxFailedAttempts;

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
     * Get activation counter value.
     * @return Activation counter value.
     */
    public long getCounter() {
        return counter;
    }

    /**
     * Set activation counter value.
     * @param counter Åctivation counter value.
     */
    public void setCounter(long counter) {
        this.counter = counter;
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

}
