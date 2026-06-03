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

import com.wultra.security.powerauth.crypto.lib.v4.dh.DhKem;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlKem;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.DefaultSharedSecretRequest;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.DefaultSharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.io.InputStream;
import java.security.Security;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SharedSecretClientTest {

    private static final ObjectMapper MAPPER = JsonMapper.builder().build();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static DefaultSharedSecret getSharedSecretImpl(SharedSecretAlgorithm algorithm) throws Exception {
        return switch (algorithm) {
            case EC_P384 -> new DefaultSharedSecret(algorithm, List.of(
                    new DhKem()
            ));
            case EC_P384_ML_L3 -> new DefaultSharedSecret(algorithm, List.of(
                    new DhKem(),
                    new MlKem(SharedSecretAlgorithm.EC_P384_ML_L3.getMlKemParameterSpec())
            ));
            case EC_P384_ML_L5 -> new DefaultSharedSecret(algorithm, List.of(
                    new DhKem(),
                    new MlKem(SharedSecretAlgorithm.EC_P384_ML_L5.getMlKemParameterSpec())
            ));
            case ML_L3 ->  new DefaultSharedSecret(algorithm, List.of(
                    new MlKem(SharedSecretAlgorithm.EC_P384_ML_L3.getMlKemParameterSpec())
            ));
            case ML_L5 ->  new DefaultSharedSecret(algorithm, List.of(
                    new MlKem(SharedSecretAlgorithm.EC_P384_ML_L5.getMlKemParameterSpec())
            ));
            case EC_P256 -> throw new Exception("Legacy algorithm doesn't use shared secret");
            default -> throw new Exception("Unsupported shared secret algorithm");
        };
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    static class ClientTestVector {
        private String clientContext;
        private DefaultSharedSecretRequest request;
        private DefaultSharedSecretResponse response;
        private String sharedSecret;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    static class ClientTestBatch {
        private SharedSecretAlgorithm algorithm;
        private List<ClientTestVector> testVectors;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    static class ClientTesData {
        private List<ClientTestBatch> testData;
    }

    @Test
    public void testHybridFromClient() throws Exception {
        /*
         Usage of this test:

         1. In PowerAuthCore project
            - Open `SharedSecretTests.cpp`
            - Enable `generateTestVectorsForServer` test method (uncomment the method in Unit test's constructor)
            - Run unit tests
            - Copy result printed in `genTestVectors_EC_P384_ML_L3()` function
            - Paste test data to `SharedSecret_Client_Vectors.json` (see below)
         2. Run this test case
            - Copy result printed in the test case
         3. In PowerAuthCore project
            - Paste result to `SharedSecret_Client_Vectors.json`
            - Run script: `src/PowerAuthTests/TestData/update-pa2-files.sh`
            - Disable `generateTestVectorsForServer` test method
            - Run unit test
         */

        InputStream stream = SharedSecretHybrid768Test.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/sharedsecret/SharedSecret_Client_Vectors.json");
        assertNotNull(stream);
        ClientTesData testData = MAPPER.readValue(stream, new TypeReference<>() {});
        assertNotNull(testData);

        for (ClientTestBatch batch : testData.getTestData()) {
            DefaultSharedSecret algorithm = getSharedSecretImpl(batch.getAlgorithm());
            for  (ClientTestVector vector : batch.getTestVectors()) {
                DefaultSharedSecretRequest request = vector.getRequest();
                // Algorithm is no in input request data
                ResponseCryptogram responseCryptogram = algorithm.generateResponseCryptogram(request);
                vector.setSharedSecret(Base64.getEncoder().encodeToString(responseCryptogram.getSecretKey().getEncoded()));
                vector.setResponse((DefaultSharedSecretResponse) responseCryptogram.getSharedSecretResponse());
            }
        }
        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(testData));
    }
}
