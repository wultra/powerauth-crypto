/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.rest.api.model;

/**
 * Response object for /pa/activation/create end-point.
 *
 * @author Petr Dvorak
 *
 */
public class ActivationCreateResponse {

    private String activationId;
    private String activationNonce;
    private String ephemeralPublicKey;
    private String encryptedServerPublicKey;
    private String encryptedServerPublicKeySignature;

    /**
     * Get activation ID
     * @return Activation ID
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID
     * @param activationId Activation ID
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get activation nonce.
     * @return Activation nonce.
     */
    public String getActivationNonce() {
        return activationNonce;
    }

    /**
     * Set activation nonce.
     * @param activationNonce Activation nonce.
     */
    public void setActivationNonce(String activationNonce) {
        this.activationNonce = activationNonce;
    }

    /**
     * Get ephemeral public key.
     * @return Ephemeral public key.
     */
    public String getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    /**
     * Set ephemeral public key.
     * @param ephemeralPublicKey Ephemeral public key.
     */
    public void setEphemeralPublicKey(String ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    /**
     * Get encrypted server public key.
     * @return Encrypted server public key.
     */
    public String getEncryptedServerPublicKey() {
        return encryptedServerPublicKey;
    }

    /**
     * Set encrypted server public key.
     * @param encryptedServerPublicKey Encrypted server public key.
     */
    public void setEncryptedServerPublicKey(String encryptedServerPublicKey) {
        this.encryptedServerPublicKey = encryptedServerPublicKey;
    }

    /**
     * Get server data signature.
     * @return Server data signature.
     */
    public String getEncryptedServerPublicKeySignature() {
        return encryptedServerPublicKeySignature;
    }

    /**
     * Set server data signature.
     * @param encryptedServerPublicKeySignature Server data signature.
     */
    public void setEncryptedServerPublicKeySignature(String encryptedServerPublicKeySignature) {
        this.encryptedServerPublicKeySignature = encryptedServerPublicKeySignature;
    }

}
