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
import com.wultra.security.powerauth.crypto.lib.util.ByteUtils;
import com.wultra.security.powerauth.crypto.lib.util.SideChannelUtils;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.exception.AeadException;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import lombok.Getter;

import java.util.Base64;
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
     * Expected length of the combined request nonce in bytes. The first 12 bytes are used as the IV for the request
     * encryption, the last 12 bytes are used as the IV for the response encryption.
     */
    private final static int NONCE_LENGTH = 24;

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
        if (!validateEncryptedRequestWithoutData(request)) {
            return false;
        }
        return request.getEncryptedData() != null;
    }

    @Override
    public boolean validateEncryptedRequestWithoutData(AeadEncryptedRequest request) {
        if (request == null) {
            return false;
        }
        if (request.getTemporaryKeyId() == null) {
            return false;
        }
        if (request.getNonce() == null) {
            return false;
        }
        if (!validateNonce(request.getNonce())) {
            return false;
        }
        return request.getTimestamp() != null;
    }

    @Override
    public boolean validateEncryptedResponse(AeadEncryptedResponse response) {
        if (response == null) {
            return false;
        }
        if (response.getEncryptedData() == null) {
            return false;
        }
        return response.getTimestamp() != null;
    }

    /**
     * Validate the combined request nonce. The server uses the first half of the nonce as the IV for decrypting the
     * request and the second half as the IV for encrypting the response, both under the same envelope key. The two
     * halves must therefore differ, otherwise the IV would be reused with the same key during the communication, which
     * would break the security guarantees of the AEAD scheme.
     *
     * @param nonceBase64 Base64-encoded combined request nonce.
     * @return {@code true} if the nonce has the expected length and the request and response nonce halves differ.
     */
    private boolean validateNonce(String nonceBase64) {
        if (nonceBase64 == null) {
            return false;
        }
        final byte[] nonce;
        try {
            nonce = Base64.getDecoder().decode(nonceBase64);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (nonce.length != NONCE_LENGTH) {
            return false;
        }
        final byte[] requestNonce = ByteUtils.subarray(nonce, 0, NONCE_LENGTH / 2);
        final byte[] responseNonce = ByteUtils.subarray(nonce, NONCE_LENGTH / 2, NONCE_LENGTH / 2);
        // The request nonce must differ from the response nonce to avoid IV reuse under the same envelope key
        return !SideChannelUtils.constantTimeAreEqual(requestNonce, responseNonce);
    }
    
}
