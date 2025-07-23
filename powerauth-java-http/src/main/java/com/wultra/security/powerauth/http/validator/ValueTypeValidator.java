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
package com.wultra.security.powerauth.http.validator;

import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility class to validate various value types, such as UUID, base64 encoded data, etc.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ValueTypeValidator {

    private static final Logger logger = LoggerFactory.getLogger(ValueTypeValidator.class);

    /**
     * Regexp for validating UUID values.
     */
    private static final String UUID_REGEX = "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";

    /**
     * Regexp for validating decimalized authentication code values.
     */
    private static final String AUTH_CODE_REGEX = "^[0-9]{8}(-[0-9]{8}){0,2}$";

    /**
     * Regexp for validating decimal strings.
     */
    private static final String DECIMAL_STRING_REGEX = "^[0-9]*$";

    /**
     * Admissible authentication code types in the header.
     */
    private static final Set<String> EXPECTED_AUTH_CODE_TYPES = new HashSet<>(Arrays.asList(
            "possession", "knowledge", "biometry",
            "possession_knowledge", "possession_biometry",
            "possession_knowledge_biometry"
    ));

    /**
     * Check if provided string is a valid UUID.
     * @param uuidCandidate UUID candidate.
     * @return True in case provided string is a valid UUID, false otherwise.
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public static boolean isValidUuid(String uuidCandidate) {
        return uuidCandidate != null && uuidCandidate.toLowerCase().matches(UUID_REGEX);
    }

    /**
     * Validate provided string that is expected to be in Base64 encoding. If the string is in Base64
     * encoding, validate for expected length of decoded bytes.
     * @param base64candidate Base64 string candidate.
     * @param expectedLength Expected length od decoded bytes.
     * @return True in case the provided string are Base64 encoded data of expected byte length,
     * false otherwise.
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public static boolean isValidBase64OfLength(String base64candidate, int expectedLength) {
        if (base64candidate != null) {
            try {
                byte[] bytes = Base64.getDecoder().decode(base64candidate);
                return bytes.length == expectedLength;
            } catch (IllegalArgumentException e) {
                logger.trace("Given string '{}' is not in base64 format.", base64candidate, e);
            }
        }

        return false;
    }

    /**
     * Validate provided string that is expected to be in Base64 encoding. If the string is in Base64
     * encoding, validate if expected length of decoded bytes is in range from-to.
     * @param base64candidate Base64 string candidate.
     * @param from Expected minimal length od decoded bytes.
     * @param to Expected maximal length od decoded bytes.
     * @return True in case the provided string are Base64 encoded data of expected byte length,
     * false otherwise.
     */
    public static boolean isValidBase64OfLengthRange(String base64candidate, int from, int to) {
        if (base64candidate != null) {
            try {
                byte[] bytes = Base64.getDecoder().decode(base64candidate);
                return bytes.length >= from && bytes.length <= to;
            } catch (IllegalArgumentException e) {
                logger.trace("Given string '{}' is not in base64 format.", base64candidate, e);
            }
        }

        return false;
    }

    /**
     * Check if the provided authentication code type value is valid.
     * @param authCodeType Authentication code type candidate.
     * @return True if the provided authentication code type is valid.
     */
    public static boolean isValidAuthCodeType(String authCodeType) {
        return authCodeType != null && EXPECTED_AUTH_CODE_TYPES.contains(authCodeType.toLowerCase());
    }

    /**
     * Validate if the provided authentication code is of a correct format.
     * @param authCode Authentication code candidate.
     * @return True if authentication code candidate has correct format, false otherwise.
     */
    public static boolean isValidAuthCodeValue(String authCode) {
        if (authCode != null) {
            switch (authCode.length()) {
                case 8, 17, 26 -> {
                    // "3.0" authentication code version uses "DECIMAL" format
                    return authCode.matches(AUTH_CODE_REGEX);
                }
                case 24, 44, 64 -> {
                    // "3.1" and later authentication code uses "BASE64" format.
                    // We don't need to validate an exact number of encoded bytes. This is due to fact,
                    // that if input string length can only be 24, 44 or 64, then the encoded output length
                    // must be 16, 32 or 48.
                    return isValidBase64OfLengthRange(authCode, 16, 48);
                }
                default -> {
                    return false;
                }
            }
        }
        return false;
    }

    /**
     * Check if the string is a decimal string of provided length range.
     * @param decimalString Decimal string candidate.
     * @param from Minimal length.
     * @param to Maximal length.
     * @return True if provided string is decimal and has expected length range.
     */
    public static boolean isDecimalString(String decimalString, int from, int to) {
        if (decimalString != null && decimalString.matches(DECIMAL_STRING_REGEX)) {
            return decimalString.length() >= from && decimalString.length() <= to;
        } else {
            return false;
        }
    }

    /**
     * Check if the provided version is a valid one.
     * @param version Version to check.
     * @return True if provided version is valid, false otherwise.
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public static boolean isValidProtocolVersion(String version) {
        return ProtocolVersion.supportedVersions().contains(version);
    }

}
