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
 * <h5>PowerAuth protocol versions:</h5>
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

    public byte[] getSessionIndex() {
        return sessionIndex;
    }

    public void setSessionIndex(byte[] sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    public byte[] getAdHocIndex() {
        return adHocIndex;
    }

    public void setAdHocIndex(byte[] adHocIndex) {
        this.adHocIndex = adHocIndex;
    }

    public byte[] getMacIndex() {
        return macIndex;
    }

    public void setMacIndex(byte[] macIndex) {
        this.macIndex = macIndex;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }

    public byte[] getMac() {
        return mac;
    }

    public void setMac(byte[] mac) {
        this.mac = mac;
    }
}
