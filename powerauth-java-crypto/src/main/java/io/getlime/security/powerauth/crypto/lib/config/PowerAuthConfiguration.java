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

import io.getlime.security.powerauth.provider.CryptoProviderUtil;

/**
 * PowerAuth cryptography configuration class.
 *
 * @author Petr Dvorak
 *
 */
public enum PowerAuthConfiguration {

    /**
     * Singleton instance
     */
    INSTANCE;

    /**
     * Instance of the KeyConvertor, a class used to convert keys to bytes and vice versa.
     */
    private CryptoProviderUtil keyConvertor;

    /**
     * Set key convertor instance.
     * @param keyConvertor Key convertor instance
     */
    public void setKeyConvertor(CryptoProviderUtil keyConvertor) {
        this.keyConvertor = keyConvertor;
    }

    /**
     * Get key convertor instance.
     * @return Key convertor instance
     */
    public CryptoProviderUtil getKeyConvertor() {
        if (keyConvertor == null) {
            throw new NullPointerException("Convertor mustn't be null! Set convertor by calling PowerAuthConfiguration.INSTANCE.setKeyConvertor().");
        }
        return keyConvertor;
    }

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

}
