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
import com.wultra.security.powerauth.crypto.lib.util.PqcKemKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.PqcKem;
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

import static org.junit.jupiter.api.Assertions.*;

public class SharedSecretHybridTest {

    private static final KeyGenerator KEY_GENERATOR_EC = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcKemKeyConvertor KEY_CONVERTOR_PQC = new PqcKemKeyConvertor();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final PqcKem pkcKem = new PqcKem();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testHybrid_Success() throws Exception {
        SharedSecretHybrid sharedSecretHybrid = new SharedSecretHybrid();
        RequestCryptogram request = sharedSecretHybrid.generateRequestCryptogram();
        assertNotNull(request);
        assertNotNull(request.getSharedSecretRequest());
        assertNotNull(request.getSharedSecretClientContext());

        KeyPair ecClientKeyPair = KEY_GENERATOR_EC.generateKeyPair(EcCurve.P384);
        KeyPair pqcClientKeyPair = pkcKem.generateKeyPair();
        SharedSecretClientContextHybrid clientContext = new SharedSecretClientContextHybrid(ecClientKeyPair.getPrivate(), pqcClientKeyPair.getPrivate());

        byte[] ecClientPublicKeyRaw = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecClientKeyPair.getPublic());
        String ecClientPublicKeyBase64 = Base64.getEncoder().encodeToString(ecClientPublicKeyRaw);
        byte[] pqcClientPublicKeyRaw = KEY_CONVERTOR_PQC.convertPublicKeyToBytes(pqcClientKeyPair.getPublic());
        String pqcClientPublicKeyBase64 = Base64.getEncoder().encodeToString(pqcClientPublicKeyRaw);
        SharedSecretRequestHybrid clientRequest = new SharedSecretRequestHybrid(ecClientPublicKeyBase64, pqcClientPublicKeyBase64);

        ResponseCryptogram serverResponse = sharedSecretHybrid.generateResponseCryptogram(clientRequest);
        assertNotNull(serverResponse);
        assertNotNull(serverResponse.getSharedSecretResponse());
        assertNotNull(serverResponse.getSecretKey());

        SecretKey serverSharedSecret = sharedSecretHybrid.computeSharedSecret(
                clientContext,
                (SharedSecretResponseHybrid) serverResponse.getSharedSecretResponse()
        );
        assertNotNull(serverSharedSecret);

        assertEquals(
                serverSharedSecret,
                serverResponse.getSecretKey()
        );
    }

    public static Stream<Map<String, String>> jsonDataEcdhe_P384_Mlkem_768_Provider() throws IOException {
        InputStream stream = SharedSecretEcdheTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/sharedsecret/ECDHE_P384_MLKEM_768_Test_Vectors.json");
        Map<String, List<Map<String, String>>> testData = MAPPER.readValue(stream, new TypeReference<>() {});
        return testData.get("ecdhe_mlkem_test_vectors").stream();
    }

    @ParameterizedTest
    @MethodSource("jsonDataEcdhe_P384_Mlkem_768_Provider")
    public void testEcdheMlkemWithTestVectors(Map<String, String> vector) throws Exception {
        SharedSecretHybrid sharedSecretHybrid = new SharedSecretHybrid();
        PrivateKey ecClientPrivateKey = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(vector.get("ecClientPrivateKey")));
        PrivateKey pqcClientPrivateKey = KEY_CONVERTOR_PQC.convertBytesToPrivateKey(Base64.getDecoder().decode(vector.get("pqcClientPrivateKey")));
        SharedSecretClientContextHybrid clientContext = new SharedSecretClientContextHybrid(ecClientPrivateKey, pqcClientPrivateKey);
        SharedSecretResponseHybrid response = new SharedSecretResponseHybrid(vector.get("ecServerPublicKey"), vector.get("pqcEncapsulation"));
        SecretKey sharedSecret = sharedSecretHybrid.computeSharedSecret(
                clientContext,
                response
        );
        assertNotNull(sharedSecret);
        assertEquals(Base64.getEncoder().encodeToString(sharedSecret.getEncoded()), vector.get("sharedKey"));
    }

}
