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
package io.getlime.security.powerauth.http;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for HTTP body normalization routine.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthHttpBodyTest {

    /**
     * Utility code for generating nonce and printing it as Base64 encoded string on console
    private byte[] genNonce() {
        final byte[] nonce = new byte[16];
        try {
            SecureRandom.getInstanceStrong().nextBytes(nonce);
        } catch (NoSuchAlgorithmException e) {
            // ignore
        }
        System.out.println("\"" + Base64.getEncoder().encodeToString(nonce) + "\"");
        return nonce;
    }**/

    @Test
    public void testSignatureBaseString() {

        // HTTP method - POST
        String method;

        // Resource ID - /pa/login
        String resourceId;

        // Random bytes - 16b generated using strong rnd generator
        byte[] nonce;

        // Request body for the login request - platform and language code, ... utf-8
        byte[] body;

        // Resulting signature base string
        String signatureBaseString;

        method = "POST";
        resourceId = "/pa/login";
        nonce = Base64.getDecoder().decode("vkueT796IGqdXlfVIJrB9A==");
        body = "{\"Platform\": \"A\",\"LanguageCode\": \"ENG\"}".getBytes(StandardCharsets.UTF_8);
        signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(method, resourceId, nonce, body);
        assertEquals(signatureBaseString, "POST&L3BhL2xvZ2lu&vkueT796IGqdXlfVIJrB9A==&eyJQbGF0Zm9ybSI6ICJBIiwiTGFuZ3VhZ2VDb2RlIjogIkVORyJ9");

        method = "GET";
        resourceId = "/pa/login";
        nonce = Base64.getDecoder().decode("t5W/nUcGPKAVUjA11ydJeQ==");
        body = "{\"Platform\": \"A\",\"LanguageCode\": \"ENG\"}".getBytes(StandardCharsets.UTF_8);
        signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(method, resourceId, nonce, body);
        assertEquals(signatureBaseString, "GET&L3BhL2xvZ2lu&t5W/nUcGPKAVUjA11ydJeQ==&eyJQbGF0Zm9ybSI6ICJBIiwiTGFuZ3VhZ2VDb2RlIjogIkVORyJ9");

        method = "POST";
        nonce = Base64.getDecoder().decode("oXcwuuRCCEHiw/pFiIg4bA==");
        body = "{\"Platform\": \"A\",\"LanguageCode\": \"ENG\"}".getBytes(StandardCharsets.UTF_8);
        signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(method, null, nonce, body);
        assertEquals(signatureBaseString, "POST&&oXcwuuRCCEHiw/pFiIg4bA==&eyJQbGF0Zm9ybSI6ICJBIiwiTGFuZ3VhZ2VDb2RlIjogIkVORyJ9");

        method = "POST";
        resourceId = "/pa/login";
        nonce = Base64.getDecoder().decode("U2EjaQ2N7KMlrghn7KL+3A==");
        body = "{\"Platform\": \"A\",\"LanguageCode\": \"ENG\"}".getBytes(StandardCharsets.UTF_8);
        signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(method, resourceId, nonce, body);
        assertEquals(signatureBaseString, "POST&L3BhL2xvZ2lu&U2EjaQ2N7KMlrghn7KL+3A==&eyJQbGF0Zm9ybSI6ICJBIiwiTGFuZ3VhZ2VDb2RlIjogIkVORyJ9");

        method = "POST";
        resourceId = "/pa/login";
        nonce = Base64.getDecoder().decode("UWtQ9nMNGtJQbZ9zx/J3FQ==");
        body = "{\"Platform\": \"A\",\"LanguageCode\": \"ENG\"}".getBytes(StandardCharsets.UTF_8);
        signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(method, resourceId, nonce, body);
        assertEquals(signatureBaseString, "POST&L3BhL2xvZ2lu&UWtQ9nMNGtJQbZ9zx/J3FQ==&eyJQbGF0Zm9ybSI6ICJBIiwiTGFuZ3VhZ2VDb2RlIjogIkVORyJ9");

        resourceId = "/pa/login";
        nonce = Base64.getDecoder().decode("UWtQ9nMNGtJQbZ9zx/J3FQ==");
        body = "{\"Platform\": \"A\",\"LanguageCode\": \"ENG\"}".getBytes(StandardCharsets.UTF_8);
        signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(null, resourceId, nonce, body);
        assertEquals(signatureBaseString, "GET&L3BhL2xvZ2lu&UWtQ9nMNGtJQbZ9zx/J3FQ==&eyJQbGF0Zm9ybSI6ICJBIiwiTGFuZ3VhZ2VDb2RlIjogIkVORyJ9");

        method = "POST";
        resourceId = "/pa/login";
        body = "{\"Platform\": \"A\",\"LanguageCode\": \"ENG\"}".getBytes(StandardCharsets.UTF_8);
        signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(method, resourceId, null, body);
        assertEquals(signatureBaseString, "POST&L3BhL2xvZ2lu&&eyJQbGF0Zm9ybSI6ICJBIiwiTGFuZ3VhZ2VDb2RlIjogIkVORyJ9");

        method = "POST";
        resourceId = "/pa/login";
        nonce = new byte[16];
        body = "{\"Platform\": \"A\",\"LanguageCode\": \"ENG\"}".getBytes(StandardCharsets.UTF_8);
        signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(method, resourceId, nonce, body);
        assertEquals(signatureBaseString, "POST&L3BhL2xvZ2lu&AAAAAAAAAAAAAAAAAAAAAA==&eyJQbGF0Zm9ybSI6ICJBIiwiTGFuZ3VhZ2VDb2RlIjogIkVORyJ9");

        method = "POST";
        resourceId = "/pa/login";
        nonce = new byte[16];
        signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(method, resourceId, nonce, null);
        assertEquals(signatureBaseString, "POST&L3BhL2xvZ2lu&AAAAAAAAAAAAAAAAAAAAAA==&");

    }
}