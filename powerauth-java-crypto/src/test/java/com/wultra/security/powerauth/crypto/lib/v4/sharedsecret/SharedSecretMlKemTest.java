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
import com.wultra.security.powerauth.crypto.lib.util.PqcKemKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextPqc;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestPqc;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponsePqc;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for shared secret calculation for ML-KEM-768.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SharedSecretMlKemTest {

    private static final PqcKemKeyConvertor KEY_CONVERTOR_PQC = new PqcKemKeyConvertor();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMlKem_Success() throws Exception {
        SharedSecretPqc sharedSecretPqc = new SharedSecretPqc();
        RequestCryptogram request = sharedSecretPqc.generateRequestCryptogram();
        assertNotNull(request);
        assertNotNull(request.getSharedSecretRequest());
        assertNotNull(request.getSharedSecretClientContext());

        SharedSecretRequestPqc clientRequest = (SharedSecretRequestPqc) request.getSharedSecretRequest();
        SharedSecretClientContextPqc clientContext = (SharedSecretClientContextPqc) request.getSharedSecretClientContext();

        ResponseCryptogram serverResponse = sharedSecretPqc.generateResponseCryptogram(clientRequest);
        assertNotNull(serverResponse);
        assertNotNull(serverResponse.getSharedSecretResponse());
        assertNotNull(serverResponse.getSecretKey());

        SecretKey derivedSharedSecret = sharedSecretPqc.computeSharedSecret(
                clientContext,
                (SharedSecretResponsePqc) serverResponse.getSharedSecretResponse()
        );
        assertNotNull(derivedSharedSecret);

        assertEquals(
                derivedSharedSecret,
                serverResponse.getSecretKey()
        );
    }

    private static Stream<Map<String, String>> jsonDataMlkem_768_Provider() throws IOException {
        InputStream stream = SharedSecretMlKemTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/sharedsecret/MLKEM_768_Test_Vectors.json");
        Map<String, List<Map<String, String>>> testData = MAPPER.readValue(stream, new TypeReference<>() {});
        return testData.get("mlkem_test_vectors").stream();
    }

    @ParameterizedTest
    @MethodSource("jsonDataMlkem_768_Provider")
    public void testEcdheMlkemWithTestVectors(Map<String, String> vector) throws Exception {
        SharedSecretPqc sharedSecretPqc = new SharedSecretPqc();
        PrivateKey pqcClientPrivateKey = KEY_CONVERTOR_PQC.convertBytesToPrivateKey(Base64.getDecoder().decode(vector.get("pqcClientPrivateKey")));
        SharedSecretClientContextPqc clientContext = new SharedSecretClientContextPqc(pqcClientPrivateKey);
        SharedSecretResponsePqc response = new SharedSecretResponsePqc(vector.get("pqcCiphertext"));
        SecretKey sharedSecret = sharedSecretPqc.computeSharedSecret(
                clientContext,
                response
        );
        assertNotNull(sharedSecret);
        assertEquals(Base64.getEncoder().encodeToString(sharedSecret.getEncoded()), vector.get("sharedSecret"));
    }

    @Test
    public void generateTestVectors() throws Exception {
        final List<Map<String, String>> vectors = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            SharedSecretPqc sharedSecretPqc = new SharedSecretPqc();
            RequestCryptogram request = sharedSecretPqc.generateRequestCryptogram();
            SharedSecretRequestPqc clientRequest = (SharedSecretRequestPqc) request.getSharedSecretRequest();
            SharedSecretClientContextPqc clientContext = (SharedSecretClientContextPqc) request.getSharedSecretClientContext();
            ResponseCryptogram serverResponse = sharedSecretPqc.generateResponseCryptogram(clientRequest);
            SecretKey derivedSharedSecret = sharedSecretPqc.computeSharedSecret(
                    clientContext,
                    (SharedSecretResponsePqc) serverResponse.getSharedSecretResponse()
            );
            Map<String, String> vector = new LinkedHashMap<>();
            vector.put("pqcClientPrivateKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPrivateKeyToBytes(clientContext.getPqcKemDecapsulationKey())));
            vector.put("pqcCiphertext", ((SharedSecretResponsePqc) serverResponse.getSharedSecretResponse()).getPqcCiphertext());
            vector.put("sharedSecret", Base64.getEncoder().encodeToString(derivedSharedSecret.getEncoded()));
            vectors.add(vector);
        }

        Map<String, Object> root = Map.of("mlkem_test_vectors", vectors);
        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root));
    }

}
