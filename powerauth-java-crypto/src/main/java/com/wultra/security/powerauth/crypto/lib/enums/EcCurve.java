/*
 * PowerAuth Crypto Library
 * Copyright 2024 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.enums;

/**
 * EC curve enumeration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public enum EcCurve {

    /**
     * Curve secp256r1.
     */
    P256("secp256r1", "SHA256withECDSA"),

    /**
     * Curve secp384r1.
     */
    P384("secp384r1", "SHA384withECDSA");

    private final String name;
    private final String ecdsaAlgorithm;

    /**
     * Constructor.
     * @param name Standardized EC curve name.
     * @param ecdsaAlgorithm EC curve ECDSA algorithm.
     */
    EcCurve(String name, String ecdsaAlgorithm) {
        this.name = name;
        this.ecdsaAlgorithm = ecdsaAlgorithm;
    }

    /**
     * Get standardized EC curve name.
     * @return Standardized EC curve name.
     */
    public String getName() {
        return name;
    }

    /**
     * EC curve ECDSA algorithm.
     * @return EC curve ECDSA algorithm
     */
    public String getEcdsaAlgorithm() {
        return ecdsaAlgorithm;
    }

}