/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.v4.encryptor.aead;

import com.wultra.security.powerauth.crypto.lib.encryptor.RequestResponseValidator;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.exception.AeadException;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import lombok.Getter;

import java.util.Set;

/**
 * The {@code AeadRequestResponseValidator} class implements request and response validation for 4.x protocol versions.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Getter
public class AeadRequestResponseValidator implements RequestResponseValidator<AeadEncryptedRequest, AeadEncryptedResponse> {

    /**
     * Protocol versions supported in this validator.
     */
    private final static Set<String> supportedVersions = Set.of("4.0");

    /**
     * Construct validator for particular protocol version.
     * @param protocolVersion Protocol version.
     * @throws AeadException In case that protocol is not supported.
     */
    public AeadRequestResponseValidator(String protocolVersion) throws AeadException {
        if (!supportedVersions.contains(protocolVersion)) {
            throw new AeadException("Unsupported protocol version " + protocolVersion);
        }
    }

    @Override
    public boolean validateEncryptedRequest(AeadEncryptedRequest request) {
        if (request == null) {
            return false;
        }
        if (request.getEncryptedData() == null) {
            return false;
        }
        if (request.getTemporaryKeyId() == null) {
            return false;
        }
        if (request.getNonce() == null) {
            return false;
        }
        return request.getTimestamp() != null;
    }

    @Override
    public boolean validateEncryptedResponse(AeadEncryptedResponse response) {
        if (response == null) {
            return false;
        }
        if (response.getEncryptedData() == null ) {
            return false;
        }
        return response.getTimestamp() != null;
    }
    
}
