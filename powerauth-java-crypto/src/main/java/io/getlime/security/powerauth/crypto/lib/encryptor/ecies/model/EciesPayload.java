/*
 * Copyright 2017 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model;

import java.security.PublicKey;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
public class EciesPayload {

    private final PublicKey ephemeralPublicKey;
    private final byte[] mac;
    private final byte[] encryptedData;

    public EciesPayload(PublicKey ephemeralPublicKey, byte[] mac, byte[] encryptedData) {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.mac = mac;
        this.encryptedData = encryptedData;
    }

    public PublicKey getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public byte[] getMac() {
        return mac;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

}
