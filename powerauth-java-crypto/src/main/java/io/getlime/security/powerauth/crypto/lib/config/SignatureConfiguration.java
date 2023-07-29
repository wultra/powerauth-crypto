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
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;

/**
 * Class that holds information about the signature configuration.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public abstract class SignatureConfiguration {

    private final PowerAuthSignatureFormat signatureFormat;

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
     * Convert PowerAuth signature format to signature configuration.
     * @param format PowerAuth signature format.
     * @return Signature configuration.
     * @throws CryptoProviderException In case of invalid signature format.
     */
    public static SignatureConfiguration forFormat(PowerAuthSignatureFormat format) throws CryptoProviderException {
        switch (format) {
            case BASE64 -> {
                return new Base64SignatureConfiguration();
            }
            case DECIMAL -> {
                return new DecimalSignatureConfiguration();
            }
        }
        throw new CryptoProviderException("Invalid or null format provided: " + format);
    }

    /**
     * Construct new decimal signature of default length.
     *
     * @return Decimal signature with default length.
     */
    public static DecimalSignatureConfiguration decimal() {
        return new DecimalSignatureConfiguration();
    }

    /**
     * Construct new decimal signature of given length.
     *
     * @param length Length.
     * @return Decimal signature with given length.
     */
    public static DecimalSignatureConfiguration decimal(Integer length) {
        return new DecimalSignatureConfiguration(length);
    }

    /**
     * Construct new Base64 signature.
     *
     * @return Base64 signature.
     */
    public static Base64SignatureConfiguration base64() {
        return new Base64SignatureConfiguration();
    }

}
