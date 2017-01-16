/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.rest.api.model.entity;

/**
 * Class representing a payload encrypted using non-personalized end-to-end encryption.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class NonPersonalizedEncryptedPayloadModel {

    private String applicationKey;
    private String sessionIndex;
    private String adHocIndex;
    private String macIndex;
    private String nonce;
    private String ephemeralPublicKey;
    private String mac;
    private String encryptedData;

    public String getApplicationKey() {
        return applicationKey;
    }

    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    public String getSessionIndex() {
        return sessionIndex;
    }

    public void setSessionIndex(String sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    public String getAdHocIndex() {
        return adHocIndex;
    }

    public void setAdHocIndex(String adHocIndex) {
        this.adHocIndex = adHocIndex;
    }

    public String getMacIndex() {
        return macIndex;
    }

    public void setMacIndex(String macIndex) {
        this.macIndex = macIndex;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(String ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }
}
