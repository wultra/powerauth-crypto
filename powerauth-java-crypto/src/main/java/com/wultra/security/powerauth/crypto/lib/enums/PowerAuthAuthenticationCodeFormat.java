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

package com.wultra.security.powerauth.crypto.lib.enums;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;

import java.util.HashMap;
import java.util.Map;

/**
 * Enum with authentication code format types.
 */
public enum PowerAuthAuthenticationCodeFormat {

    /**
     * Each authentication code factor is represented by one decimal, zero-padded, 8-digit long number. If the final authentication code
     * is composed from more than one factor, then the dash character {@code "-"} is the separator between the factors. For example:
     * <ul>
     *     <li>One factor: {@code 88457234}</li>
     *     <li>Two factors: {@code 88457234-00630125}</li>
     * </ul>
     * <p>
     * This type of formatting is currently used in the following scenarios:
     * <ul>
     *     <li>For legacy {@code 3.0} version of online authentication codes.</li>
     *     <li>For all versions of offline authentication codes.</li>
     * </ul>
     */
    DECIMAL,
    /**
     * Each authentication code factor is represented by 16-bytes long binary data. If the authentication code is composed from more than
     * one factor, then the binary sequences are concatenated one after another. The whole authentication code is then represented
     * as one Base64 string with {@code "="} as a padding character. For example:
     * <ul>
     *     <li>One factor: {@code MDEyMzQ1Njc4OWFiY2RlZg==}</li>
     *     <li>Two factors: {@code MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=}</li>
     * </ul>
     * This type of formatting is used for {@code 3.1} version of online authentication codes and newer.
     */
    BASE64;

    /**
     * Map that translates string into {@link PowerAuthAuthenticationCodeFormat} enumeration.
     */
    private final static Map<String, PowerAuthAuthenticationCodeFormat> stringToEnumMap = new HashMap<>();

    /**
     * Map that translates version string into {@link PowerAuthAuthenticationCodeFormat} enumeration.
     */
    private final static Map<String, PowerAuthAuthenticationCodeFormat> versionToEnumMap = new HashMap<>();

    static {
        // Prepare string to enumeration mapping
        for (PowerAuthAuthenticationCodeFormat format : PowerAuthAuthenticationCodeFormat.values()) {
            stringToEnumMap.put(format.toString(), format);
        }
        // Prepare version to enumeration mapping
        versionToEnumMap.put("3.0", DECIMAL);
        versionToEnumMap.put("3.1", BASE64);
        versionToEnumMap.put("3.2", BASE64);
        versionToEnumMap.put("3.3", BASE64);
        versionToEnumMap.put("4.0", BASE64);
    }

    /**
     * Get authentication code format for authentication code version.
     *
     * @param authenticationCodeVersion Authentication code version to be calculated, or validated.
     * @return Authentication code format for given version.
     * @throws GenericCryptoException In case that null or unknown format is provided.
     */
    public static PowerAuthAuthenticationCodeFormat getFormatForVersion(String authenticationCodeVersion) throws GenericCryptoException {
        if (authenticationCodeVersion != null) {
            // Try to translate known version into the format.
            final PowerAuthAuthenticationCodeFormat format = versionToEnumMap.get(authenticationCodeVersion);
            if (format != null) {
                return format;
            }
            // Fallback in case that we increased the general protocol version, but not updated this function.
            // All versions above 3.1 should require Base64 formatting.
            try {
                final double numericVersion = Double.parseDouble(authenticationCodeVersion);
                if (numericVersion > 3.1) {
                    return BASE64;
                }
            } catch (NumberFormatException ex) {
                // Version is in wrong format.
                throw new GenericCryptoException("Unsupported authentication code version: " + authenticationCodeVersion, ex);
            }
            // Version is not known
            throw new GenericCryptoException("Unsupported authentication code version: " + authenticationCodeVersion);
        }
        // Version is not specified.
        throw new GenericCryptoException("Unspecified authentication code version");
    }

    /**
     * Converts string into {@link PowerAuthAuthenticationCodeFormat} enumeration. Function returns {@code null} in case that
     * such conversion is not possible.
     * <p>
     * You can use {@link #toString()} function as opposite, to convert enumeration into its string representation.
     *
     * @param value String representation of the enumeration.
     * @return {@link PowerAuthAuthenticationCodeFormat} enumeration or {@code null} if the conversion is not possible.
     */
    public static PowerAuthAuthenticationCodeFormat getEnumFromString(String value) {
        if (value != null) {
            return stringToEnumMap.get(value.toUpperCase());
        }
        return null;
    }

    /**
     * Compare enumeration to another string.
     * @param otherName Other string to compare
     * @return {@code true} if other string is equal to this enumeration's string representation.
     */
    public boolean equalsName(String otherName) {
        return toString().equalsIgnoreCase(otherName);
    }
}
