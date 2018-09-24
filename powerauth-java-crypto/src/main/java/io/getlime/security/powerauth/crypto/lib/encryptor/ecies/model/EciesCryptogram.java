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

/**
 * The EciesCryptogram structure represents cryptogram transmitted over the network.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesCryptogram {

    private final byte[] key;
    private final byte[] mac;
    private final byte[] body;

    /**
     * ECIES cryptogram constructor.
     *
     * @param key Ephemeral public key.
     * @param mac MAC computed for key and data.
     * @param body Encrypted data.
     */
    public EciesCryptogram(byte[] key, byte[] mac, byte[] body) {
        this.key = key;
        this.mac = mac;
        this.body = body;
    }

    /**
     * Get ephemeral public key bytes. The value is optional for response data.
     *
     * @return Ephemeral public key bytes.
     */
    public byte[] getKey() {
        return key;
    }

    /**
     * Get the MAC computed for key and data.
     *
     * @return MAC computed for key and data.
     */
    public byte[] getMac() {
        return mac;
    }

    /**
     * Get the encrypted data.
     *
     * @return Encrypted data.
     */
    public byte[] getBody() {
        return body;
    }
}
