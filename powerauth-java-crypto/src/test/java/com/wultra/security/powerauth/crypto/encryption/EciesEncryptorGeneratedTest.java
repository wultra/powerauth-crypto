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
package com.wultra.security.powerauth.crypto.encryption;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.ecies.ClientEciesEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.*;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ServerEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.E2eeEncryptorTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Generate test vectors for E2EE in versions 3.x of the protocol.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesEncryptorGeneratedTest {

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Add crypto providers.
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void generateTestVectorsApplicationScope30() throws Exception {
        generateTestVectorsApplicationScope("3.0");
    }

    @Test
    public void generateTestVectorsApplicationScope31() throws Exception {
        generateTestVectorsApplicationScope("3.1");
    }

    @Test
    public void generateTestVectorsApplicationScope32() throws Exception {
        generateTestVectorsApplicationScope("3.2");
    }

    @Test
    public void generateTestVectorsApplicationScope33() throws Exception {
        generateTestVectorsApplicationScope("3.3");
    }

    @Test
    public void generateTestVectorsActivationScope30() throws Exception {
        generateTestVectorsActivationScope("3.0");
    }

    @Test
    public void generateTestVectorsActivationScope31() throws Exception {
        generateTestVectorsActivationScope("3.1");
    }

    @Test
    public void generateTestVectorsActivationScope32() throws Exception {
        generateTestVectorsActivationScope("3.2");
    }

    @Test
    public void generateTestVectorsActivationScope33() throws Exception {
        generateTestVectorsActivationScope("3.3");
    }

    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ApplicationScope_Provider30")
    public void testVectorsApplicationScope_Success30(Map<String, String> vector) throws Exception {
        testVectors_Success(vector, "3.0", EncryptorId.APPLICATION_SCOPE_GENERIC);
    }

    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ApplicationScope_Provider31")
    public void testVectorsApplicationScope_Success31(Map<String, String> vector) throws Exception {
        testVectors_Success(vector, "3.1", EncryptorId.APPLICATION_SCOPE_GENERIC);
    }

    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ApplicationScope_Provider32")
    public void testVectorsApplicationScope_Success32(Map<String, String> vector) throws Exception {
        testVectors_Success(vector, "3.2", EncryptorId.APPLICATION_SCOPE_GENERIC);
    }

    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ApplicationScope_Provider33")
    public void testVectorsApplicationScope_Success33(Map<String, String> vector) throws Exception {
        testVectors_Success(vector, "3.3", EncryptorId.APPLICATION_SCOPE_GENERIC);
    }
    
    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ActivationScope_Provider30")
    public void testVectorsActivationScope_Success30(Map<String, String> vector) throws Exception {
        testVectors_Success(vector, "3.0", EncryptorId.ACTIVATION_SCOPE_GENERIC);
    }

    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ActivationScope_Provider31")
    public void testVectorsActivationScope_Success31(Map<String, String> vector) throws Exception {
        testVectors_Success(vector, "3.1", EncryptorId.ACTIVATION_SCOPE_GENERIC);
    }

    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ActivationScope_Provider32")
    public void testVectorsActivationScope_Success32(Map<String, String> vector) throws Exception {
        testVectors_Success(vector, "3.2", EncryptorId.ACTIVATION_SCOPE_GENERIC);
    }

    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ActivationScope_Provider33")
    public void testVectorsActivationScope_Success33(Map<String, String> vector) throws Exception {
        testVectors_Success(vector, "3.3", EncryptorId.ACTIVATION_SCOPE_GENERIC);
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ApplicationScope_Provider30() throws IOException {
        return jsonDataE2ee_ApplicationScope_Provider("3.0");
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ApplicationScope_Provider31() throws IOException {
        return jsonDataE2ee_ApplicationScope_Provider("3.1");
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ApplicationScope_Provider32() throws IOException {
        return jsonDataE2ee_ApplicationScope_Provider("3.2");
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ApplicationScope_Provider33() throws IOException {
        return jsonDataE2ee_ApplicationScope_Provider("3.3");
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ApplicationScope_Provider(String protocolVersion) throws IOException {
        InputStream stream = E2eeEncryptorTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v3/encryptor/E2ee_Application_Scope_Test_Vectors_" + protocolVersion.replace(".", "") + ".json");
        Map<String, List<Map<String, String>>> testData = MAPPER.readValue(stream, new TypeReference<>() {});
        return testData.get("e2ee_test_vectors_application_scope").stream();
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ActivationScope_Provider30() throws IOException {
        return jsonDataE2ee_ActivationScope_Provider("3.0");
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ActivationScope_Provider31() throws IOException {
        return jsonDataE2ee_ActivationScope_Provider("3.1");
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ActivationScope_Provider32() throws IOException {
        return jsonDataE2ee_ActivationScope_Provider("3.2");
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ActivationScope_Provider33() throws IOException {
        return jsonDataE2ee_ActivationScope_Provider("3.3");
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ActivationScope_Provider(String protocolVersion) throws IOException {
        InputStream stream = E2eeEncryptorTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v3/encryptor/E2ee_Activation_Scope_Test_Vectors_" + protocolVersion.replace(".", "") + ".json");
        Map<String, List<Map<String, String>>> testData = MAPPER.readValue(stream, new TypeReference<>() {});
        return testData.get("e2ee_test_vectors_activation_scope").stream();
    }

    private void testVectors_Success(Map<String, String> vector, String protocolVersion, EncryptorId encryptorId) throws Exception {
        final boolean activationScope = encryptorId == EncryptorId.ACTIVATION_SCOPE_GENERIC;
        final String activationId = activationScope ? vector.get("activationId") : null;
        final String applicationKey = vector.get("applicationKey");
        final String serverPublicKeyBase64 = vector.get("serverPublicKey");
        final byte[] sharedInfo2Base = Base64.getDecoder().decode(vector.get("sharedInfo2Base"));
        final PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode(serverPublicKeyBase64));
        final String temporaryKeyId = vector.get("temporaryKeyId");
        final EncryptorParameters parameters = new EncryptorParameters(protocolVersion, applicationKey, activationId, temporaryKeyId);
        final EncryptorSecrets clientSecrets = new ClientEciesSecrets(serverPublicKey, sharedInfo2Base);
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, parameters, clientSecrets);
        final String requestData = vector.get("requestData");
        final String requestEphemeralPublicKeyBase64 = vector.get("requestEphemeralPublicKey");
        final Long timestampRequest;
        if (vector.containsKey("timestampRequest")) {
            timestampRequest = Long.parseLong(vector.get("timestampRequest"));
        } else {
            timestampRequest = null;
        }
        final String requestNonce = vector.getOrDefault("requestNonce", null);
        final String requestMac = vector.get("requestMac");
        final String encryptedDataRequest = vector.get("encryptedDataRequest");
        final byte[] envelopeKey = Base64.getDecoder().decode(vector.get("envelopeKey"));

        final EciesEncryptedRequest encryptedRequest = new EciesEncryptedRequest(temporaryKeyId, requestEphemeralPublicKeyBase64, encryptedDataRequest, requestMac, requestNonce, timestampRequest);
        final EncryptorSecrets serverSecrets = new ServerEciesSecrets(envelopeKey, sharedInfo2Base);
        final ServerEncryptor<EncryptedRequest, EncryptedResponse> serverEncryptor = ENCRYPTOR_FACTORY.getServerEncryptor(encryptorId, parameters, serverSecrets);
        final byte[] decryptedRequest = serverEncryptor.decryptRequest(encryptedRequest);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedRequest);

        final String responseData = vector.get("responseData");
        final Long timestampResponse;
        if (vector.containsKey("timestampResponse")) {
            timestampResponse = Long.parseLong(vector.get("timestampResponse"));
        } else {
            timestampResponse = null;
        }
        final String encryptedDataResponse = vector.get("encryptedDataResponse");
        final String responseNonce = vector.getOrDefault("responseNonce", null);
        final String responseMac = vector.get("responseMac");

        final EciesEncryptedResponse encryptedResponse = new EciesEncryptedResponse(encryptedDataResponse, responseMac, responseNonce, timestampResponse);
        // Configure client encryptor state for tests
        final EciesEnvelopeKey clientEnvelopeKey = new EciesEnvelopeKey(envelopeKey, Base64.getDecoder().decode(requestEphemeralPublicKeyBase64));
        final Field envelopeKeyField = ClientEciesEncryptor.class.getDeclaredField("envelopeKey");
        envelopeKeyField.setAccessible(true);
        envelopeKeyField.set(clientEncryptor, clientEnvelopeKey);
        if (requestNonce != null) {
            final Field requestNonceField = ClientEciesEncryptor.class.getDeclaredField("requestNonce");
            requestNonceField.setAccessible(true);
            requestNonceField.set(clientEncryptor, Base64.getDecoder().decode(requestNonce));
        }

        final byte[] decryptedResponse = clientEncryptor.decryptResponse(encryptedResponse);
        assertArrayEquals(responseData.getBytes(StandardCharsets.UTF_8), decryptedResponse);
    }

    private void generateTestVectorsApplicationScope(String protocolVersion) throws Exception {
        System.out.println("{\n  \"e2ee_test_vectors_application_scope\": [");
        for (int i = 0; i < 25; i++) {
            generateTestVectorForScope(EncryptorId.APPLICATION_SCOPE_GENERIC, protocolVersion);
            if (i < 24) {
                System.out.println(",");
            } else {
                System.out.println();
            }
        }
        System.out.println("  ]\n}");
    }

    private void generateTestVectorsActivationScope(String protocolVersion) throws Exception {
        System.out.println("{\n  \"e2ee_test_vectors_activation_scope\": [");
        for (int i = 0; i < 25; i++) {
            generateTestVectorForScope(EncryptorId.ACTIVATION_SCOPE_GENERIC, protocolVersion);
            if (i < 24) {
                System.out.println(",");
            } else {
                System.out.println();
            }
        }
        System.out.println("  ]\n}");
    }

    private void generateTestVectorForScope(EncryptorId encryptorId, String protocolVersion) throws Exception {
        final String applicationKey = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(16));
        final String applicationSecret = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(16));
        final String temporaryKeyId = protocolVersion.equals("3.3") ? UUID.randomUUID().toString() : null;
        final boolean activationScope = encryptorId == EncryptorId.ACTIVATION_SCOPE_GENERIC;
        final String activationId = activationScope ? UUID.randomUUID().toString() : null;

        final EncryptorParameters parameters = new EncryptorParameters(protocolVersion, applicationKey, activationId, temporaryKeyId);

        final KeyPair serverKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P256);
        final byte[] serverPublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P256, serverKeyPair.getPublic());
        final byte[] transportKey = activationScope ? KEY_GENERATOR.generateRandomSecretKey(16).getEncoded() : null;

        final EncryptorSecrets serverSecrets = new ServerEciesSecrets(serverKeyPair.getPrivate(), applicationSecret, transportKey);
        final EncryptorSecrets clientSecrets = new ClientEciesSecrets(serverKeyPair.getPublic(), applicationSecret, transportKey);
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, parameters, clientSecrets);
        final ServerEncryptor<EncryptedRequest, EncryptedResponse> serverEncryptor = ENCRYPTOR_FACTORY.getServerEncryptor(encryptorId, parameters, serverSecrets);
        final String requestData = "test_request";
        final EciesEncryptedRequest encryptedRequest = (EciesEncryptedRequest) clientEncryptor.encryptRequest(requestData.getBytes(StandardCharsets.UTF_8));
        final byte[] decryptedRequest = serverEncryptor.decryptRequest(encryptedRequest);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedRequest);
        final String responseData = "test_response";
        final EciesEncryptedResponse encryptedResponse = (EciesEncryptedResponse) serverEncryptor.encryptResponse(responseData.getBytes(StandardCharsets.UTF_8));
        final ServerEciesSecrets serverEciesSecrets = (ServerEciesSecrets) serverEncryptor.deriveSecretsForExternalEncryptor(encryptedRequest);

        System.out.println("    {");
        System.out.println("      \"protocolVersion\": \"" + protocolVersion + "\",");
        System.out.println("      \"encryptorId\": \"" + encryptorId + "\",");
        System.out.println("      \"encryptorScope\": \"" + (activationScope ? "ACTIVATION_SCOPE" : "APPLICATION_SCOPE") + "\",");
        if (activationScope) {
            System.out.println("      \"activationId\": \"" + activationId + "\",");
        }
        System.out.println("      \"applicationKey\": \"" + applicationKey + "\",");
        System.out.println("      \"applicationSecret\": \"" + applicationSecret + "\",");
        if (protocolVersion.equals("3.3")) {
            System.out.println("      \"temporaryKeyId\": \"" + temporaryKeyId + "\",");
        }
        System.out.println("      \"envelopeKey\": \"" + Base64.getEncoder().encodeToString(serverEciesSecrets.getEnvelopeKey()) + "\",");
        System.out.println("      \"sharedInfo2Base\": \"" + Base64.getEncoder().encodeToString(serverEciesSecrets.getSharedInfo2Base()) + "\",");
        if (activationScope) {
            System.out.println("      \"transportKey\": \"" + Base64.getEncoder().encodeToString(transportKey) + "\",");
        }
        System.out.println("      \"requestData\": \"" + requestData + "\",");
        System.out.println("      \"requestEphemeralPublicKey\": \"" + encryptedRequest.getEphemeralPublicKey() + "\",");
        System.out.println("      \"serverPublicKey\": \"" + Base64.getEncoder().encodeToString(serverPublicKeyBytes) + "\",");
        if (protocolVersion.equals("3.3") || protocolVersion.equals("3.2")) {
            System.out.println("      \"timestampRequest\": \"" + encryptedRequest.getTimestamp() + "\",");
        }
        if (protocolVersion.equals("3.3") || protocolVersion.equals("3.2") || protocolVersion.equals("3.1")) {
            System.out.println("      \"requestNonce\": \"" + encryptedRequest.getNonce() + "\",");
        }
        System.out.println("      \"requestMac\": \"" + encryptedRequest.getMac() + "\",");
        System.out.println("      \"encryptedDataRequest\": \"" + encryptedRequest.getEncryptedData() + "\",");
        System.out.println("      \"responseData\": \"" + responseData + "\",");
        if (protocolVersion.equals("3.3") || protocolVersion.equals("3.2")) {
            System.out.println("      \"timestampResponse\": \"" + encryptedResponse.getTimestamp() + "\",");
            System.out.println("      \"responseNonce\": \"" + encryptedResponse.getNonce() + "\",");
        }
        System.out.println("      \"responseMac\": \"" + encryptedResponse.getMac() + "\",");
        System.out.println("      \"encryptedDataResponse\": \"" + encryptedResponse.getEncryptedData() + "\"");
        System.out.print("    }");
    }

}
