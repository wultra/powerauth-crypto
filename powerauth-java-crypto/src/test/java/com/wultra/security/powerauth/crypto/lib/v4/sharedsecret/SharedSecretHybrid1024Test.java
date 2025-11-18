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
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.Kem;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcKemKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.dh.DhKem;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlKem;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlKemKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.DefaultSharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.DefaultSharedSecretRequest;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.DefaultSharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for shared secret calculation for hybrid ECDHE on curve P-384 with ML-KEM-1024.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SharedSecretHybrid1024Test {

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcKemKeyConvertor KEY_CONVERTOR_PQC = new MlKemKeyConvertor();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testHybrid_Success() throws Exception {
        List<Kem> kems = List.of(new DhKem(), new MlKem(SharedSecretAlgorithm.EC_P384_ML_L5.getMlKemParameterSpec()));
        DefaultSharedSecret sharedSecret = new DefaultSharedSecret(SharedSecretAlgorithm.EC_P384_ML_L5, kems);
        RequestCryptogram request = sharedSecret.generateRequestCryptogram();
        assertNotNull(request);
        assertNotNull(request.getSharedSecretRequest());
        assertNotNull(request.getSharedSecretClientContext());

        DefaultSharedSecretRequest clientRequest = (DefaultSharedSecretRequest) request.getSharedSecretRequest();
        DefaultSharedSecretClientContext clientContext = (DefaultSharedSecretClientContext) request.getSharedSecretClientContext();

        ResponseCryptogram serverResponse = sharedSecret.generateResponseCryptogram(clientRequest);
        assertNotNull(serverResponse);
        assertNotNull(serverResponse.getSharedSecretResponse());
        assertNotNull(serverResponse.getSecretKey());

        SecretKey derivedSharedSecret = sharedSecret.computeSharedSecret(
                clientContext,
                (DefaultSharedSecretResponse) serverResponse.getSharedSecretResponse()
        );
        assertNotNull(derivedSharedSecret);

        assertArrayEquals(
                derivedSharedSecret.getEncoded(),
                serverResponse.getSecretKey().getEncoded()
        );
    }

    private static Stream<Map<String, String>> jsonDataEcdhe_P384_Mlkem_1024_Provider() throws IOException {
        InputStream stream = SharedSecretHybrid1024Test.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/sharedsecret/ECDHE_P384_MLKEM_1024_Test_Vectors.json");
        Map<String, List<Map<String, String>>> testData = MAPPER.readValue(stream, new TypeReference<>() {});
        return testData.get("ecdhe_mlkem_test_vectors").stream();
    }

    @ParameterizedTest
    @MethodSource("jsonDataEcdhe_P384_Mlkem_1024_Provider")
    public void testEcdheMlkemWithTestVectors(Map<String, String> vector) throws Exception {
        List<Kem> kems = List.of(new DhKem(), new MlKem(SharedSecretAlgorithm.EC_P384_ML_L5.getMlKemParameterSpec()));
        DefaultSharedSecret sharedSecret = new DefaultSharedSecret(SharedSecretAlgorithm.EC_P384_ML_L5, kems);
        PrivateKey ecClientPrivateKey = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(vector.get("ecClientPrivateKey")));
        PrivateKey pqcClientPrivateKey = KEY_CONVERTOR_PQC.convertBytesToPrivateKey(Base64.getDecoder().decode(vector.get("pqcClientPrivateKey")));
        DefaultSharedSecretClientContext clientContext = new DefaultSharedSecretClientContext(List.of(ecClientPrivateKey, pqcClientPrivateKey));
        byte[] salt = Base64.getDecoder().decode(vector.get("salt"));
        DefaultSharedSecretResponse response = new DefaultSharedSecretResponse(salt, List.of(vector.get("ecServerPublicKey"), vector.get("pqcCiphertext")));
        SecretKey sharedSecretKey = sharedSecret.computeSharedSecret(clientContext, response);
        assertNotNull(sharedSecretKey);
        assertEquals(
                vector.get("sharedSecret"),
                Base64.getEncoder().encodeToString(sharedSecretKey.getEncoded())
        );
    }

    @Test
    public void generateTestVectors() throws Exception {
        List<Map<String, String>> vectors = new ArrayList<>();
        List<Kem> kems = List.of(
                new DhKem(),
                new MlKem(SharedSecretAlgorithm.EC_P384_ML_L5.getMlKemParameterSpec())
        );
        DefaultSharedSecret sharedSecret = new DefaultSharedSecret(SharedSecretAlgorithm.EC_P384_ML_L5, kems);
        for (int i = 0; i < 100; i++) {
            RequestCryptogram request = sharedSecret.generateRequestCryptogram();
            DefaultSharedSecretRequest clientRequest = (DefaultSharedSecretRequest) request.getSharedSecretRequest();
            DefaultSharedSecretClientContext clientContext = (DefaultSharedSecretClientContext) request.getSharedSecretClientContext();
            ResponseCryptogram serverResponse = sharedSecret.generateResponseCryptogram(clientRequest);
            Map<String, String> vector = new LinkedHashMap<>();
            vector.put("ecClientPrivateKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPrivateKeyToBytes(clientContext.getDecapsulationKeys().get(0))));
            vector.put("pqcClientPrivateKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPrivateKeyToBytes(clientContext.getDecapsulationKeys().get(1))));
            vector.put("ecServerPublicKey", ((DefaultSharedSecretResponse)serverResponse.getSharedSecretResponse()).getEncapsulatedKeys().get(0));
            vector.put("pqcCiphertext", ((DefaultSharedSecretResponse)serverResponse.getSharedSecretResponse()).getEncapsulatedKeys().get(1));
            vector.put("salt", Base64.getEncoder().encodeToString(((DefaultSharedSecretResponse) serverResponse.getSharedSecretResponse()).getSalt()));
            vector.put("sharedSecret", Base64.getEncoder().encodeToString(serverResponse.getSecretKey().getEncoded()));
            vectors.add(vector);
        }

        Map<String, Object> root = Map.of("ecdhe_mlkem_test_vectors", vectors);
        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root));
    }

}
