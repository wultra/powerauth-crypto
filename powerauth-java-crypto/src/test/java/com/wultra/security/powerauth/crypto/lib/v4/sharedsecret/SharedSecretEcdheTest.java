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

package com.wultra.security.powerauth.crypto.lib.v4.sharedsecret;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SharedSecretEcdheTest {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testEcdhe_Success() throws Exception {
        SharedSecretEcdhe sharedSecretEcdhe = new SharedSecretEcdhe();
        RequestCryptogram request = sharedSecretEcdhe.generateRequestCryptogram();
        assertNotNull(request);
        assertNotNull(request.getSharedSecretRequest());
        assertNotNull(request.getSharedSecretClientContext());

        KeyPair ecClientKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P384);
        SharedSecretClientContextEcdhe clientContext = new SharedSecretClientContextEcdhe(ecClientKeyPair.getPrivate());

        byte[] ecClientPublicKeyRaw = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecClientKeyPair.getPublic());
        String ecClientPublicKeyBase64 = Base64.getEncoder().encodeToString(ecClientPublicKeyRaw);
        SharedSecretRequestEcdhe clientRequest = new SharedSecretRequestEcdhe(ecClientPublicKeyBase64);

        ResponseCryptogram serverResponse = sharedSecretEcdhe.generateResponseCryptogram(clientRequest);
        assertNotNull(serverResponse);
        assertNotNull(serverResponse.getSharedSecretResponse());
        assertNotNull(serverResponse.getSecretKey());

        SecretKey serverSharedSecret = sharedSecretEcdhe.computeSharedSecret(
                clientContext,
                (SharedSecretResponseEcdhe) serverResponse.getSharedSecretResponse()
        );
        assertNotNull(serverSharedSecret);

        assertEquals(
                serverSharedSecret,
                serverResponse.getSecretKey()
        );
    }

    private static Stream<Map<String, String>> jsonDataEcdhe_P384_Provider() throws IOException  {
        InputStream stream = SharedSecretEcdheTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/sharedsecret/ECDHE_P384_Test_Vectors.json");
        Map<String, List<Map<String, String>>> testData = MAPPER.readValue(stream, new TypeReference<>() {});
        return testData.get("ecdhe_test_vectors").stream();
    }

    @ParameterizedTest
    @MethodSource("jsonDataEcdhe_P384_Provider")
    public void testEcdheWithTestVectors(Map<String, String> vector) throws Exception {
        SharedSecretEcdhe sharedSecretEcdhe = new SharedSecretEcdhe();
        PrivateKey clientPrivateKey = KEY_CONVERTOR.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(vector.get("ecClientPrivateKey")));
        SharedSecretClientContextEcdhe clientContext = new SharedSecretClientContextEcdhe(clientPrivateKey);
        SharedSecretResponseEcdhe response = new SharedSecretResponseEcdhe(vector.get("ecServerPublicKey"));
        SecretKey sharedSecret = sharedSecretEcdhe.computeSharedSecret(
                clientContext,
                response
        );
        assertNotNull(sharedSecret);
        assertEquals(Base64.getEncoder().encodeToString(sharedSecret.getEncoded()), vector.get("sharedKey"));
    }

}
