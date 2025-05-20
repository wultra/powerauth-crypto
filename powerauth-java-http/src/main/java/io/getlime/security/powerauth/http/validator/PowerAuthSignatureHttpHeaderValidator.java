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

import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;

/**
 * Validator class for {@link io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthSignatureHttpHeaderValidator {

    /**
     * Validate PowerAuth signature HTTP header.
     * @param header PowerAuth signature HTTP header.
     * @throws InvalidPowerAuthHttpHeaderException Thrown in case PowerAuth signature HTTP header is invalid.
     */
    public static void validate(PowerAuthSignatureHttpHeader header) throws InvalidPowerAuthHttpHeaderException {

        // Check if the parsing was successful
        if (header == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_INVALID_EMPTY");
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

        // Check signature type
        final String signatureType = header.getSignatureType();
        if (signatureType == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_TYPE_EMPTY");
        }

        // Check if signature type has correct format
        if (!ValueTypeValidator.isValidSignatureType(signatureType)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_TYPE_INVALID");
        }

        // Check signature
        final String signature = header.getSignature();
        if (signature == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_EMPTY");
        }

        // Check if signature has correct format
        if (!ValueTypeValidator.isValidSignatureValue(signature)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_INVALID");
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
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_VERSION_EMPTY");
        }

        // Check that version is correct
        if (!ValueTypeValidator.isValidProtocolVersion(version)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_VERSION_INVALID");
        }

    }

}