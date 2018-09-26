/*
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

import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;

/**
 * Validator class for {@link PowerAuthEncryptionHttpHeader}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthEncryptionHttpHeaderValidator {

    public static void validate(PowerAuthEncryptionHttpHeader header) throws InvalidPowerAuthHttpHeaderException {

        // Check if the parsing was successful
        if (header == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_ENCRYPTION_INVALID_EMPTY");
        }

        // Check application key
        String applicationKey = header.getApplicationKey();
        if (applicationKey == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_ENCRYPTION_APPLICATION_KEY_EMPTY");
        }

        // Check application key size
        if (!ValueTypeValidator.isValidBase64OfLength(applicationKey, 16)) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_ENCRYPTION_APPLICATION_KEY_INVALID");
        }

        String activationId = header.getActivationId();

        // Activation ID is null in application scope, thus null value is allowed
        if (activationId != null) {
            // Check if activation ID has correct UUID format
            if (!ValueTypeValidator.isValidUuid(activationId)) {
                throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_ENCRYPTION_ACTIVATION_ID_INVALID");
            }
        }

        // Check that version is present
        String version = header.getVersion();

        if (version == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_ENCRYPTION_VERSION_EMPTY");
        }

    }

}
