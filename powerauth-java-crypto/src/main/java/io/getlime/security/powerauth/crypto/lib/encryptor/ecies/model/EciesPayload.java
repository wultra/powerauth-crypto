/*
 * PowerAuth Crypto Library
 * Copyright 2023 Wultra s.r.o.
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

import lombok.AllArgsConstructor;
import lombok.Value;

/**
 * The EciesPayload structure represents ECIES payload transmitted over the network.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Value
@AllArgsConstructor
public class EciesPayload {

    EciesCryptogram cryptogram;
    EciesParameters parameters;

    /**
     * Constructor for V3.0 and V3.1 protocol versions of ECIES structure.
     * @param ephemeralPublicKey Ephemeral public key.
     * @param mac Message authentication code.
     * @param encryptedData Encrypted data.
     * @param nonce Nonce.
     */
    public EciesPayload(byte[] ephemeralPublicKey, byte[] mac, byte[] encryptedData, byte[] nonce) {
        cryptogram = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData);
        parameters = new EciesParameters(nonce, null, null);
    }

    /**
     * Constructor for V3.2 protocol version of ECIES structure.
     * @param ephemeralPublicKey Ephemeral public key.
     * @param mac Message authentication code.
     * @param encryptedData Encrypted data.
     * @param nonce Nonce.
     * @param associatedData Associated data for ECIES.
     * @param timestamp Unix timestamp in milliseconds.
     */
    public EciesPayload(byte[] ephemeralPublicKey, byte[] mac, byte[] encryptedData, byte[] nonce, byte[] associatedData, Long timestamp) {
        cryptogram = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData);
        parameters = new EciesParameters(nonce, associatedData, timestamp);
    }

}