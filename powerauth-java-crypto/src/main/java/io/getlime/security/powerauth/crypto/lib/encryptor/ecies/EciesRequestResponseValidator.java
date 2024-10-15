/*
 * PowerAuth Crypto Library
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.crypto.lib.encryptor.ecies;

import io.getlime.security.powerauth.crypto.lib.encryptor.RequestResponseValidator;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import lombok.Getter;

import java.util.Set;

/**
 * The {@code EciesRequestResponseValidator} class implements request and response validation for 3.x protocol versions.
 */
@Getter
public class EciesRequestResponseValidator implements RequestResponseValidator {
    /**
     * Protocol versions supported in this validator.
     */
    private final static Set<String> supportedVersions = Set.of("3.3", "3.2", "3.1", "3.0");

    /**
     * Indicate that request must contain temporaryKeyId. This is valid for protocol V3.3+.
     */
    private final boolean useTemporaryKeys;
    /**
     * Indicate that request and response must contain timestamp and nonce. This is valid for protocol V3.2+.
     */
    private final boolean useTimestamp;
    /**
     * Indicate that request must contain nonce. This is valid for protocol V3.1+.
     */
    private final boolean useNonceForRequest;

    /**
     * Construct validator for particular protocol version.
     * @param protocolVersion Protocol version.
     * @throws EncryptorException In case that protocol is not supported.
     */
    public EciesRequestResponseValidator(String protocolVersion) throws EncryptorException {
        if (!supportedVersions.contains(protocolVersion)) {
            throw new EncryptorException("Unsupported protocol version " + protocolVersion);
        }
        this.useTemporaryKeys = "3.3".equals(protocolVersion);
        this.useTimestamp = "3.3".equals(protocolVersion) || "3.2".equals(protocolVersion);
        this.useNonceForRequest = "3.3".equals(protocolVersion) || "3.2".equals(protocolVersion) || "3.1".equals(protocolVersion);
    }

    @Override
    public boolean validateEncryptedRequest(EncryptedRequest request) {
        if (request == null) {
            return false;
        }
        if (request.getEphemeralPublicKey() == null || request.getEncryptedData() == null || request.getMac() == null) {
            return false;
        }
        if (useTemporaryKeys == (request.getTemporaryKeyId() == null)) {
            return false;
        }
        if (useNonceForRequest == (request.getNonce() == null)) {
            // Fails when nonce is missing in 3.1+
            // Fails when nonce is present in 3.0
            return false;
        }
        // Next statement return false when:
        // - timestamp is missing in 3.2+
        // - timestamp is present in 3.0 and 3.1
        return useTimestamp == (request.getTimestamp() != null);
    }

    @Override
    public boolean validateEncryptedResponse(EncryptedResponse response) {
        if (response == null) {
            return false;
        }
        if (response.getEncryptedData() == null || response.getMac() == null) {
            return false;
        }
        if (useTimestamp) {
            // 3.2+
            return response.getNonce() != null && response.getTimestamp() != null;
        } else {
            // 3.0, 3.1 should not contain nonce and timestamp in response
            return response.getNonce() == null && response.getTimestamp() == null;
        }
    }
}
