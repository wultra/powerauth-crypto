/*
 * PowerAuth Crypto Library
 * Copyright 2019 Wultra s.r.o.
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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class representing recovery code seed information.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RecoverySeed {

    private byte[] nonce;
    private Map<Integer, Long> pukDerivationIndexes = new LinkedHashMap<>();

    /**
     * Default constructor.
     */
    public RecoverySeed() {
    }

    /**
     * Constructor with nonce bytes and PUK derivation indexes.
     * @param nonce Nonce.
     * @param pukDerivationIndexes PUK derivation indexes.
     */
    public RecoverySeed(byte[] nonce, Map<Integer, Long> pukDerivationIndexes) {
        this.nonce = nonce;
        this.pukDerivationIndexes = new LinkedHashMap<>(pukDerivationIndexes);
    }

    /**
     * Get nonce bytes.
     * @return Nonce bytes.
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Set nonce bytes.
     * @param nonce Nonce bytes.
     */
    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    /**
     * Get PUK derivation indexes.
     * @return PUK derivation indexes.
     */
    public Map<Integer, Long> getPukDerivationIndexes() {
        return new LinkedHashMap<>(pukDerivationIndexes);
    }

    /**
     * Set PUK derivation indexes.
     * @param pukDerivationIndexes PUK derivation indexes.
     */
    public void setPukDerivationIndexes(Map<Integer, Long> pukDerivationIndexes) {
        this.pukDerivationIndexes = new LinkedHashMap<>(pukDerivationIndexes);
    }
}
