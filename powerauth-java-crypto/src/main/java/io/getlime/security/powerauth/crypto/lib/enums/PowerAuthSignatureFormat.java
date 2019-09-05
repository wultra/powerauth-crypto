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

package io.getlime.security.powerauth.crypto.lib.enums;

import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;

/**
 * Enum with signature format types.
 */
public enum PowerAuthSignatureFormat {
    /**
     * Each signature's factor is represented by one decimal, zero-padded, 8-digit long number. If the final signature
     * is composed from more than one factor, then the dash character {@code "-"} is the separator between the factors. For example:
     * <ul>
     *     <li>One factor: {@code 88457234}</li>
     *     <li>Two factors: {@code 88457234-00630125}</li>
     * </ul>
     * <p>
     * This type of formatting is currently used in the following scenarios:
     * <ul>
     *     <li>For legacy {@code 2.0}, {@code 2.1} and {@code 3.0} versions of online signatures.</li>
     *     <li>For all versions of offline signatures.</li>
     * </ul>
     */
    DECIMAL,
    /**
     * Each signature's factor is represented by 16-bytes long binary data. If the signature is composed from more than
     * one factor, then the binary sequences are concatenated one after another. The whole signature is then represented
     * as one Base64 string with {@code "="} as a padding character. For example:
     * <ul>
     *     <li>One factor: {@code MDEyMzQ1Njc4OWFiY2RlZg==}</li>
     *     <li>Two factors: {@code MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=}</li>
     * </ul>
     * This type of formatting is currently used for {@code 3.1} version of online signatures.
     */
    BASE64;

    /**
     * Get signature format for signature version.
     *
     * @param signatureVersion Signature version to be calculated, or validated.
     * @return Signature format for given version.
     * @throws GenericCryptoException In case that null or unknown format is provided.
     */
    public static PowerAuthSignatureFormat getFormatForSignatureVersion(String signatureVersion) throws GenericCryptoException {
        if (signatureVersion != null) {
            if ("3.1".equals(signatureVersion)) {
                return BASE64;
            }
            if ("3.0".equals(signatureVersion) || "2.1".equals(signatureVersion) || "2.0".equals(signatureVersion)) {
                return DECIMAL;
            }
            // Fallback in case that we increased the general protocol version, but not updated this function.
            // All versions above 3.1 should require Base64 formatting.
            try {
                final double numericVersion = Double.parseDouble(signatureVersion);
                if (numericVersion > 3.1) {
                    return BASE64;
                }
            } catch (NumberFormatException ex) {
                // Version is in wrong format.
                throw new GenericCryptoException("Unsupported signature version: " + signatureVersion, ex);
            }
            // Version is not known
            throw new GenericCryptoException("Unsupported signature version: " + signatureVersion);
        }
        // Version is not specified.
        throw new GenericCryptoException("Unspecified signature version");
    }
}
