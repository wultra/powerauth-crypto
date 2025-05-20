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
package io.getlime.security.powerauth.crypto.lib.config;

/**
 * PowerAuth cryptography configuration class.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthConfiguration {

    /**
     * Name of cryptography provider used by PowerAuth.
     */
    public static final String CRYPTO_PROVIDER_NAME = "BC";

    /**
     * How many iterations should be used for PBKDF2 key derivation.
     */
    public static final int PBKDF_ITERATIONS = 10000;

    /**
     * Length of device public key fingerprint (number of decimal numbers representing fingerprint)
     */
    public static final int FINGERPRINT_LENGTH = 8;

    /**
     * Length of signature factor in decimal formatted signature (number of decimal numbers representing signature)
     */
    public static final int SIGNATURE_DECIMAL_LENGTH = 8;

    /**
     * Length of signature factor in Base64 formatted signature (number of bytes encoded to Base64)
     */
    public static final int SIGNATURE_BINARY_LENGTH = 16;

    /**
     * Number of bytes required for the signature counter data.
     */
    public static final int SIGNATURE_COUNTER_LENGTH = 16;

    /**
     * Maximum number of signature factors allowed in multi-factor signature
     */
    public static final int MAX_SIGNATURE_KEYS_COUNT = 3;
}
