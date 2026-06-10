/*
 * PowerAuth Crypto Library
 * Copyright 2026 Wultra s.r.o.
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

import com.wultra.security.powerauth.crypto.lib.v4.encryptor.exception.AeadException;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link AeadRequestResponseValidator}, in particular the combined request nonce validation that prevents
 * IV reuse between the request and response encryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class AeadRequestResponseValidatorTest {

    private static final String TEMPORARY_KEY_ID = "temp-key-id";
    private static final String ENCRYPTED_DATA = "ZW5jcnlwdGVkRGF0YQ==";
    private static final long TIMESTAMP = 1717500000000L;

    private AeadRequestResponseValidator validator;

    @BeforeEach
    void setUp() throws AeadException {
        validator = new AeadRequestResponseValidator("4.0");
    }

    @Test
    void constructorRejectsUnsupportedProtocolVersion() {
        assertThrows(AeadException.class, () -> new AeadRequestResponseValidator("3.3"));
    }

    @Test
    void validRequestPasses() {
        final AeadEncryptedRequest request = request(nonce(repeat((byte) 0x01), repeat((byte) 0x02)));
        assertTrue(validator.validateEncryptedRequest(request));
        assertTrue(validator.validateEncryptedRequestWithoutData(request));
    }

    @Test
    void requestWithEqualNonceHalvesIsRejected() {
        // Request nonce equal to response nonce would reuse the IV under the same envelope key
        final byte[] half = repeat((byte) 0x07);
        final AeadEncryptedRequest request = request(nonce(half, half));
        assertFalse(validator.validateEncryptedRequest(request));
        assertFalse(validator.validateEncryptedRequestWithoutData(request));
    }

    @Test
    void requestWithTooShortNonceIsRejected() {
        final String shortNonce = Base64.getEncoder().encodeToString(new byte[12]);
        final AeadEncryptedRequest request = request(shortNonce);
        assertFalse(validator.validateEncryptedRequest(request));
        assertFalse(validator.validateEncryptedRequestWithoutData(request));
    }

    @Test
    void requestWithTooLongNonceIsRejected() {
        final String longNonce = Base64.getEncoder().encodeToString(new byte[48]);
        final AeadEncryptedRequest request = request(longNonce);
        assertFalse(validator.validateEncryptedRequest(request));
        assertFalse(validator.validateEncryptedRequestWithoutData(request));
    }

    @Test
    void requestWithMalformedBase64NonceIsRejected() {
        final AeadEncryptedRequest request = request("not-valid-base64!!!");
        assertFalse(validator.validateEncryptedRequest(request));
        assertFalse(validator.validateEncryptedRequestWithoutData(request));
    }

    @Test
    void requestWithNullNonceIsRejected() {
        final AeadEncryptedRequest request = request(null);
        assertFalse(validator.validateEncryptedRequest(request));
        assertFalse(validator.validateEncryptedRequestWithoutData(request));
    }

    @Test
    void requestWithNullTemporaryKeyIdIsRejected() {
        final AeadEncryptedRequest request = new AeadEncryptedRequest(null, ENCRYPTED_DATA, nonce(repeat((byte) 0x01), repeat((byte) 0x02)), TIMESTAMP);
        assertFalse(validator.validateEncryptedRequest(request));
    }

    @Test
    void requestWithNullTimestampIsRejected() {
        final AeadEncryptedRequest request = new AeadEncryptedRequest(TEMPORARY_KEY_ID, ENCRYPTED_DATA, nonce(repeat((byte) 0x01), repeat((byte) 0x02)), null);
        assertFalse(validator.validateEncryptedRequest(request));
    }

    @Test
    void requestWithoutEncryptedDataFailsFullValidationButPassesWithoutData() {
        final AeadEncryptedRequest request = new AeadEncryptedRequest(TEMPORARY_KEY_ID, null, nonce(repeat((byte) 0x01), repeat((byte) 0x02)), TIMESTAMP);
        assertFalse(validator.validateEncryptedRequest(request));
        assertTrue(validator.validateEncryptedRequestWithoutData(request));
    }

    @Test
    void nullRequestIsRejected() {
        assertFalse(validator.validateEncryptedRequest(null));
        assertFalse(validator.validateEncryptedRequestWithoutData(null));
    }

    @Test
    void validResponsePasses() {
        final AeadEncryptedResponse response = new AeadEncryptedResponse(ENCRYPTED_DATA, TIMESTAMP);
        assertTrue(validator.validateEncryptedResponse(response));
    }

    @Test
    void responseWithoutDataOrTimestampIsRejected() {
        assertFalse(validator.validateEncryptedResponse(null));
        assertFalse(validator.validateEncryptedResponse(new AeadEncryptedResponse(null, TIMESTAMP)));
        assertFalse(validator.validateEncryptedResponse(new AeadEncryptedResponse(ENCRYPTED_DATA, null)));
    }

    private static AeadEncryptedRequest request(String nonce) {
        return new AeadEncryptedRequest(TEMPORARY_KEY_ID, ENCRYPTED_DATA, nonce, TIMESTAMP);
    }

    private static String nonce(byte[] requestNonce, byte[] responseNonce) {
        final byte[] combined = new byte[requestNonce.length + responseNonce.length];
        System.arraycopy(requestNonce, 0, combined, 0, requestNonce.length);
        System.arraycopy(responseNonce, 0, combined, requestNonce.length, responseNonce.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    private static byte[] repeat(byte value) {
        final byte[] result = new byte[12];
        Arrays.fill(result, value);
        return result;
    }

}
