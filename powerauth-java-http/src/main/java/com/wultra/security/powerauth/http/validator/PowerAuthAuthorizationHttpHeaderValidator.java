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

import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;

/**
 * Validator class for {@link PowerAuthAuthorizationHttpHeader}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthAuthorizationHttpHeaderValidator {

    /**
     * Validate PowerAuth authorization HTTP header.
     * @param header PowerAuth authorization HTTP header.
     * @throws InvalidPowerAuthHttpHeaderException Thrown in case PowerAuth authorization HTTP header is invalid.
     */
    public static void validate(PowerAuthAuthorizationHttpHeader header) throws InvalidPowerAuthHttpHeaderException {

        // Check if the parsing was successful
        if (header == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_AUTHORIZATION_INVALID_EMPTY");
        }

        // Check activation ID
        final String activationId = header.getActivationId();
        if (activationId == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_ACTIVATION_ID_EMPTY");
        }

        // Check if activation ID is valid UUIDv4
        if (!ValueTypeValidator.isValidUuid(activationId)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_ACTIVATION_ID_INVALID");
        }

        // Check nonce
        final String nonce = header.getNonce();
        if (nonce == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_NONCE_EMPTY");
        }

        // Check if nonce has correct format
        if (!ValueTypeValidator.isValidBase64OfLength(nonce, 16)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_NONCE_INVALID");
        }

        final String authCodeType = header.getAuthCodeType();
        if (authCodeType == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_AUTH_CODE_TYPE_EMPTY");
        }

        // Check if authorization code type has correct format
        if (!ValueTypeValidator.isValidAuthCodeType(authCodeType)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_AUTH_CODE_TYPE_INVALID");
        }

        // Check authorization code
        final String authCode = header.getAuthCode();
        if (authCode == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_AUTH_CODE_EMPTY");
        }

        // Check if authentication code has correct format
        if (!ValueTypeValidator.isValidAuthCodeValue(authCode)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_AUTH_CODE_INVALID");
        }

        // Check application key.
        final String applicationKey = header.getApplicationKey();
        if (applicationKey == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_APPLICATION_EMPTY");
        }

        // Check if application key has correct format
        if (!ValueTypeValidator.isValidBase64OfLength(applicationKey, 16)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_APPLICATION_INVALID");
        }

        // Check that version is present
        final String version = header.getVersion();
        if (version == null || version.isEmpty()) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_AUTHORIZATION_VERSION_EMPTY");
        }

        // Check that version is correct
        if (!ValueTypeValidator.isValidProtocolVersion(version)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_AUTHORIZATION_VERSION_INVALID");
        }

    }

}