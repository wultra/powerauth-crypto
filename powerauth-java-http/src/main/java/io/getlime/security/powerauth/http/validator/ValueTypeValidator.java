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
package io.getlime.security.powerauth.http.validator;

import com.google.common.io.BaseEncoding;

import java.util.Arrays;
import java.util.List;

/**
 * Utility class to validate various value types, such as UUID, base64 encoded data, etc.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ValueTypeValidator {

    private static final String uuidRegex = "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
    private static final String signatureRegex = "^[0-9]{8}(-[0-9]{8}){0,2}$";

    /**
     * Check if provided string is a valid UUID.
     * @param uuidCandidate UUID candidate.
     * @return True in case provided string is a valid UUID, false otherwise.
     */
    public static boolean isValidUuid(String uuidCandidate) {
        return uuidCandidate != null && uuidCandidate.toLowerCase().matches(uuidRegex);
    }

    /**
     * Validate provided string that is expected to be in Base64 encoding. If the string is in Base64
     * encoding, validate for expected length of decoded bytes.
     * @param base64candidate Base64 string candidate.
     * @param expectedLength Expected length od decoded bytes.
     * @return True in case the provided string are Base64 encoded data of expected byte length,
     * false otherwise.
     */
    public static boolean isValidBase64OfLength(String base64candidate, int expectedLength) {
        final BaseEncoding base64 = BaseEncoding.base64();
        if (base64candidate != null && base64.canDecode(base64candidate)) {
            byte[] bytes = base64.decode(base64candidate);
            return bytes.length == expectedLength;
        } else {
            return false;
        }
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
        final BaseEncoding base64 = BaseEncoding.base64();
        if (base64candidate != null && base64.canDecode(base64candidate)) {
            byte[] bytes = base64.decode(base64candidate);
            return bytes.length >= from && bytes.length <= to;
        } else {
            return false;
        }
    }

    /**
     * Check if the provided signature type value is valid.
     * @param signatureType Signature type candidate.
     * @return True if the provided signature type is valid.
     */
    public static boolean isValidSignatureType(String signatureType) {
        List<String> expectedSignatureTypes = Arrays.asList(
                "possession", "knowledge", "biometry",
                "possession_knowledge", "possession_biometry",
                "possession_knowledge_biometry"
        );
        return signatureType != null && expectedSignatureTypes.contains(signatureType.toLowerCase());
    }

    /**
     * Validate if the provided signature is of a correct format.
     * @param signature Signature candidate.
     * @return True if signature candidate has correct format, false otherwise.
     */
    public static boolean isValidSignatureValue(String signature) {
        return signature != null && signature.matches(signatureRegex);
    }

    /**
     * Check if the string is a decimal string of provided length range.
     * @param decimalString Decimal string candidate.
     * @param from Minimal length.
     * @param to Maximal length.
     * @return True if provided string is decimal and has expected length range.
     */
    public static boolean isDecimalString(String decimalString, int from, int to) {
        if (decimalString != null && decimalString.matches("^[0-9]*$")) {
            return decimalString.length() >= from && decimalString.length() <= to;
        } else {
            return false;
        }
    }

}
