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
package io.getlime.security.powerauth.crypto.lib.config;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class that holds information about the signature configuration.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class SignatureConfiguration {

    /**
     * Key used for retrieving expected length of the signature component.
     */
    public static final String DECIMAL_SIGNATURE_COMPONENT_LENGTH = "DECIMAL_SIGNATURE_COMPONENT_LENGTH";

    private final PowerAuthSignatureFormat signatureFormat;
    private final Map<String, Object> signatureParameters = new LinkedHashMap<>();

    /**
     * Constructor with the signature format.
     *
     * @param signatureFormat Signature format.
     */
    public SignatureConfiguration(PowerAuthSignatureFormat signatureFormat) {
        this.signatureFormat = signatureFormat;
    }

    /**
     * Get signature format.
     * @return Signature format.
     */
    public PowerAuthSignatureFormat getSignatureFormat() {
        return signatureFormat;
    }

    /**
     * Get integer with a given key from the configuration parameter map.
     * @param key Key to obtain.
     * @return Integer value, or null in case the value is not present.
     */
    public Integer getInteger(String key) {
        return (Integer) signatureParameters.get(key);
    }

    /**
     * Get integer value with a given key to the configuration parameter map.
     * @param key Key to insert.
     * @param val Value to insert.
     */
    public void putInteger(String key, Integer val) {
        signatureParameters.put(key, val);
    }

}
