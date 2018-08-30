/*
 * Copyright 2016 Wultra s.r.o.
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

import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;

/**
 * Validator class for {@link io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader}.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthTokenHttpHeaderValidator {

    public static void validate(PowerAuthTokenHttpHeader header) throws InvalidPowerAuthHttpHeaderException {

        // Check if the parsing was successful
        if (header == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_TOKEN_INVALID_EMPTY");
        }

        // Check token ID
        String tokenId = header.getTokenId();
        if (tokenId == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_TOKEN_ID_EMPTY");
        }

        // Check if token ID has correct UUID format
        if (!ValueTypeValidator.isValidUuid(tokenId)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_TOKEN_ID_INVALID");
        }

        // Check token digest
        String tokenDigest = header.getTokenDigest();
        if (tokenDigest == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_TOKEN_DIGEST_EMPTY");
        }

        // Check if token digest has correct format
        if (!ValueTypeValidator.isValidBase64OfLength(tokenDigest, 32)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_TOKEN_DIGEST_INVALID");
        }

        // Check nonce
        String nonce = header.getNonce();
        if (nonce == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_TOKEN_NONCE_EMPTY");
        }

        // Check if nonce has correct format
        if (!ValueTypeValidator.isValidBase64OfLength(nonce, 16)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_TOKEN_NONCE_INVALID");
        }

        // Check timestamp
        String timestamp = header.getTimestamp();
        if (timestamp == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_TOKEN_TIMESTAMP_EMPTY");
        }

        // Check if timestamp has correct format
        if (!ValueTypeValidator.isDecimalString(timestamp, 9, 15)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_TOKEN_TIMESTAMP_INVALID");
        }

    }

}
