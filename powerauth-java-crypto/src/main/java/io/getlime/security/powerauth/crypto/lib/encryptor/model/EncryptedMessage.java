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
package io.getlime.security.powerauth.crypto.lib.encryptor.model;

/**
 * Class representing a base encrypted message, with attributes that are
 * required for PowerAuth 2.0 E2EE to work.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * Warning: this class will be removed in the future, use ECIES encryption for PowerAuth protocol version 3.0 or higher.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class EncryptedMessage {

    private byte[] sessionIndex;
    private byte[] adHocIndex;
    private byte[] macIndex;
    private byte[] nonce;
    private byte[] encryptedData;
    private byte[] mac;

    /**
     * Get session index.
     * @return Session index.
     */
    public byte[] getSessionIndex() {
        return sessionIndex;
    }

    /**
     * Set session index.
     * @param sessionIndex Session index.
     */
    public void setSessionIndex(byte[] sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    /**
     * Get ad-hoc index.
     * @return Ad-hoc index.
     */
    public byte[] getAdHocIndex() {
        return adHocIndex;
    }

    /**
     * Set ad-hoc index.
     * @param adHocIndex Ad-hoc index.
     */
    public void setAdHocIndex(byte[] adHocIndex) {
        this.adHocIndex = adHocIndex;
    }

    /**
     * Get MAC index.
     * @return MAC index.
     */
    public byte[] getMacIndex() {
        return macIndex;
    }

    /**
     * Set MAC index.
     * @param macIndex MAC index.
     */
    public void setMacIndex(byte[] macIndex) {
        this.macIndex = macIndex;
    }

    /**
     * Get nonce.
     * @return Nonce.
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Set nonce.
     * @param nonce Nonce.
     */
    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    /**
     * Get encrypted data.
     * @return Encrypted data.
     */
    public byte[] getEncryptedData() {
        return encryptedData;
    }

    /**
     * Set encrypted data.
     * @param encryptedData Encrypted data.
     */
    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }

    /**
     * Get MAC.
     * @return MAC.
     */
    public byte[] getMac() {
        return mac;
    }

    /**
     * Set MAC.
     * @param mac MAC.
     */
    public void setMac(byte[] mac) {
        this.mac = mac;
    }
}
