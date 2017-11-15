/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthSignatureHttpHeaderValidator {

    public static void validate(PowerAuthSignatureHttpHeader header) throws InvalidPowerAuthHttpHeaderException {

        // Check if the parsing was successful
        if (header == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_INVALID_EMPTY");
        }

        // Check activation ID
        String activationId = header.getActivationId();
        if (activationId == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_ACTIVATION_ID_EMPTY");
        }

        // Check nonce
        String nonce = header.getNonce();
        if (nonce == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_NONCE_EMPTY");
        }

        // Check signature type
        String signatureType = header.getSignatureType();
        if (signatureType == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_TYPE_EMPTY");
        }

        // Check signature
        String signature = header.getSignature();
        if (signature == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_EMPTY");
        }

        // Check application key.
        String applicationKey = header.getApplicationKey();
        if (applicationKey == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_APPLICATION_EMPTY");
        }

    }

}