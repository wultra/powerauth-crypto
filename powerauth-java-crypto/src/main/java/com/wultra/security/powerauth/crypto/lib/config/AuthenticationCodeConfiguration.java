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
package com.wultra.security.powerauth.crypto.lib.config;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthAuthenticationCodeFormat;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;

/**
 * Class that holds information about authentication code configuration.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public abstract class AuthenticationCodeConfiguration {

    private final PowerAuthAuthenticationCodeFormat authenticationCodeFormat;

    /**
     * Constructor with the authentication code format.
     *
     * @param authenticationCodeFormat Authentication code format.
     */
    public AuthenticationCodeConfiguration(PowerAuthAuthenticationCodeFormat authenticationCodeFormat) {
        this.authenticationCodeFormat = authenticationCodeFormat;
    }

    /**
     * Get authentication code format.
     * @return Authentication code format.
     */
    public PowerAuthAuthenticationCodeFormat getAuthenticationCodeFormat() {
        return authenticationCodeFormat;
    }

    /**
     * Convert PowerAuth authentication code format to authentication code configuration.
     * @param format PowerAuth authentication code format.
     * @return Authentication code configuration.
     * @throws CryptoProviderException In case of invalid authentication code format.
     */
    public static AuthenticationCodeConfiguration forFormat(PowerAuthAuthenticationCodeFormat format) throws CryptoProviderException {
        switch (format) {
            case BASE64 -> {
                return new Base64AuthenticationCodeConfiguration();
            }
            case DECIMAL -> {
                return new DecimalAuthenticationCodeConfiguration();
            }
        }
        throw new CryptoProviderException("Invalid or null format provided: " + format);
    }

    /**
     * Construct new decimal authentication code of default length.
     *
     * @return Decimal authentication code with default length.
     */
    public static DecimalAuthenticationCodeConfiguration decimal() {
        return new DecimalAuthenticationCodeConfiguration();
    }

    /**
     * Construct new decimal authentication code of given length.
     *
     * @param length Length.
     * @return Decimal authentication code with given length.
     */
    public static DecimalAuthenticationCodeConfiguration decimal(Integer length) {
        return new DecimalAuthenticationCodeConfiguration(length);
    }

    /**
     * Construct new Base64 authentication code.
     *
     * @return Base64 authentication code.
     */
    public static Base64AuthenticationCodeConfiguration base64() {
        return new Base64AuthenticationCodeConfiguration();
    }

}
