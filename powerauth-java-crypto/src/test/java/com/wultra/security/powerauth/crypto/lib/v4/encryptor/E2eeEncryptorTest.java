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

package com.wultra.security.powerauth.crypto.lib.v4.encryptor;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.*;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.aead.ClientAeadEncryptor;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.*;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretHybrid;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test of AEAD encryptor for V4 end-to-end encryption scheme.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class E2eeEncryptorTest {

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testApplicationScope_Success() throws Exception {
        final EncryptorId encryptorId = EncryptorId.APPLICATION_SCOPE_GENERIC;
        final String applicationKey = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(16));
        final String applicationSecret = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(16));
        final String temporaryKeyId = UUID.randomUUID().toString();
        final EncryptorParameters parameters = new EncryptorParameters("4.0", applicationKey, null, temporaryKeyId);
        final byte[] envelopeKey = deriveSecretKey().getEncoded();
        final EncryptorSecrets secrets = new AeadSecrets(envelopeKey, applicationSecret);
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, parameters, secrets);
        clientEncryptor.configureSecrets(secrets);
        final String requestData = "test_request";
        final AeadEncryptedRequest encryptedRequest = (AeadEncryptedRequest) clientEncryptor.encryptRequest(requestData.getBytes(StandardCharsets.UTF_8));
        assertNotNull(encryptedRequest.getEncryptedData());
        assertNotNull(encryptedRequest.getTemporaryKeyId());
        assertNotNull(encryptedRequest.getTimestamp());
        assertNotNull(encryptedRequest.getNonce());

        final ServerEncryptor<EncryptedRequest, EncryptedResponse> serverEncryptor = ENCRYPTOR_FACTORY.getServerEncryptor(encryptorId, parameters, secrets);
        serverEncryptor.configureSecrets(secrets);
        final byte[] decryptedRequest = serverEncryptor.decryptRequest(encryptedRequest);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedRequest);

        final String responseData = "test_response";
        final AeadEncryptedResponse encryptedResponse = (AeadEncryptedResponse) serverEncryptor.encryptResponse(responseData.getBytes(StandardCharsets.UTF_8));
        assertNotNull(encryptedResponse.getEncryptedData());
        assertNotNull(encryptedResponse.getTimestamp());

        final byte[] decryptedResponse = clientEncryptor.decryptResponse(encryptedResponse);
        assertArrayEquals(responseData.getBytes(StandardCharsets.UTF_8), decryptedResponse);
    }

    @Test
    public void testActivationScope_Success() throws Exception {
        final EncryptorId encryptorId = EncryptorId.ACTIVATION_SCOPE_GENERIC;
        final String applicationKey = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(16));
        final String applicationSecret = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(16));
        final String temporaryKeyId = UUID.randomUUID().toString();
        final String activationId = UUID.randomUUID().toString();
        final EncryptorParameters parameters = new EncryptorParameters("4.0", applicationKey, activationId, temporaryKeyId);
        final byte[] envelopeKey = deriveSecretKey().getEncoded();
        final SecretKey sharedInfo2Key = KEY_GENERATOR.generateRandomSecretKey(32);
        final EncryptorSecrets secrets = new AeadSecrets(envelopeKey, applicationSecret, sharedInfo2Key.getEncoded());
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, parameters, secrets);
        clientEncryptor.configureSecrets(secrets);
        final String requestData = "test_request";
        final AeadEncryptedRequest encryptedRequest = (AeadEncryptedRequest) clientEncryptor.encryptRequest(requestData.getBytes(StandardCharsets.UTF_8));
        assertNotNull(encryptedRequest.getEncryptedData());
        assertNotNull(encryptedRequest.getTemporaryKeyId());
        assertNotNull(encryptedRequest.getTimestamp());
        assertNotNull(encryptedRequest.getNonce());

        final ServerEncryptor<EncryptedRequest, EncryptedResponse> serverEncryptor = ENCRYPTOR_FACTORY.getServerEncryptor(encryptorId, parameters, secrets);
        serverEncryptor.configureSecrets(secrets);
        final byte[] decryptedRequest = serverEncryptor.decryptRequest(encryptedRequest);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedRequest);

        final String responseData = "test_response";
        final AeadEncryptedResponse encryptedResponse = (AeadEncryptedResponse) serverEncryptor.encryptResponse(responseData.getBytes(StandardCharsets.UTF_8));
        assertNotNull(encryptedResponse.getEncryptedData());
        assertNotNull(encryptedResponse.getTimestamp());

        final byte[] decryptedResponse = clientEncryptor.decryptResponse(encryptedResponse);
        assertArrayEquals(responseData.getBytes(StandardCharsets.UTF_8), decryptedResponse);
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ApplicationScope_Provider() throws IOException {
        InputStream stream = E2eeEncryptorTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/encryptor/E2ee_Application_Scope_Test_Vectors.json");
        Map<String, List<Map<String, String>>> testData = MAPPER.readValue(stream, new TypeReference<>() {});
        return testData.get("e2ee_test_vectors_application_scope").stream();
    }

    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ApplicationScope_Provider")
    public void testVectorsApplicationScope_Success(Map<String, String> vector) throws Exception {
        final EncryptorId encryptorId = EncryptorId.APPLICATION_SCOPE_GENERIC;
        final String applicationKey = vector.get("applicationKey");
        final String applicationSecret = vector.get("applicationSecret");
        final String temporaryKeyId = vector.get("temporaryKeyId");
        final EncryptorParameters parameters = new EncryptorParameters("4.0", applicationKey, null, temporaryKeyId);
        final byte[] envelopeKey = Base64.getDecoder().decode(vector.get("envelopeKey"));
        final EncryptorSecrets secrets = new AeadSecrets(envelopeKey, applicationSecret);
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, parameters, secrets);
        clientEncryptor.configureSecrets(secrets);
        final String requestData = vector.get("requestData");
        final Long timestampRequest = Long.parseLong(vector.get("timestampRequest"));
        final String nonce = vector.get("nonce");
        final String encryptedDataRequest = vector.get("encryptedDataRequest");
        Field nonceField = ClientAeadEncryptor.class.getDeclaredField("nonce");
        nonceField.setAccessible(true);
        nonceField.set(clientEncryptor, Base64.getDecoder().decode(nonce));

        final AeadEncryptedRequest encryptedRequest = new AeadEncryptedRequest(temporaryKeyId, encryptedDataRequest, nonce, timestampRequest);
        final ServerEncryptor<EncryptedRequest, EncryptedResponse> serverEncryptor = ENCRYPTOR_FACTORY.getServerEncryptor(encryptorId, parameters, secrets);
        serverEncryptor.configureSecrets(secrets);
        final byte[] decryptedRequest = serverEncryptor.decryptRequest(encryptedRequest);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedRequest);

        final String responseData = vector.get("responseData");
        final Long timestampResponse = Long.parseLong(vector.get("timestampResponse"));
        final String encryptedDataResponse = vector.get("encryptedDataResponse");

        final AeadEncryptedResponse encryptedResponse = new AeadEncryptedResponse(encryptedDataResponse, timestampResponse);
        final byte[] decryptedResponse = clientEncryptor.decryptResponse(encryptedResponse);
        assertArrayEquals(responseData.getBytes(StandardCharsets.UTF_8), decryptedResponse);
    }

    private static Stream<Map<String, String>> jsonDataE2ee_ActivationScope_Provider() throws IOException {
        InputStream stream = E2eeEncryptorTest.class.getResourceAsStream("/com/wultra/security/powerauth/crypto/lib/v4/encryptor/E2ee_Activation_Scope_Test_Vectors.json");
        Map<String, List<Map<String, String>>> testData = MAPPER.readValue(stream, new TypeReference<>() {});
        return testData.get("e2ee_test_vectors_activation_scope").stream();
    }

    @ParameterizedTest
    @MethodSource("jsonDataE2ee_ActivationScope_Provider")
    public void testVectorsActivationScope_Success(Map<String, String> vector) throws Exception {
        final EncryptorId encryptorId = EncryptorId.ACTIVATION_SCOPE_GENERIC;
        final String applicationKey = vector.get("applicationKey");
        final String applicationSecret = vector.get("applicationSecret");
        final String temporaryKeyId = vector.get("temporaryKeyId");
        final String activationId = vector.get("activationId");
        final EncryptorParameters parameters = new EncryptorParameters("4.0", applicationKey, activationId, temporaryKeyId);
        final byte[] envelopeKey = Base64.getDecoder().decode(vector.get("envelopeKey"));
        final byte[] sharedInfo2Key = Base64.getDecoder().decode(vector.get("sharedInfo2Key"));
        final EncryptorSecrets secrets = new AeadSecrets(envelopeKey, applicationSecret, sharedInfo2Key);
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, parameters, secrets);
        clientEncryptor.configureSecrets(secrets);
        final String requestData = vector.get("requestData");
        final Long timestampRequest = Long.parseLong(vector.get("timestampRequest"));
        final String nonce = vector.get("nonce");
        final String encryptedDataRequest = vector.get("encryptedDataRequest");
        Field nonceField = ClientAeadEncryptor.class.getDeclaredField("nonce");
        nonceField.setAccessible(true);
        nonceField.set(clientEncryptor, Base64.getDecoder().decode(nonce));

        final AeadEncryptedRequest encryptedRequest = new AeadEncryptedRequest(temporaryKeyId, encryptedDataRequest, nonce, timestampRequest);
        final ServerEncryptor<EncryptedRequest, EncryptedResponse> serverEncryptor = ENCRYPTOR_FACTORY.getServerEncryptor(encryptorId, parameters, secrets);
        serverEncryptor.configureSecrets(secrets);
        final byte[] decryptedRequest = serverEncryptor.decryptRequest(encryptedRequest);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedRequest);

        final String responseData = vector.get("responseData");
        final Long timestampResponse = Long.parseLong(vector.get("timestampResponse"));
        final String encryptedDataResponse = vector.get("encryptedDataResponse");

        final AeadEncryptedResponse encryptedResponse = new AeadEncryptedResponse(encryptedDataResponse, timestampResponse);
        final byte[] decryptedResponse = clientEncryptor.decryptResponse(encryptedResponse);
        assertArrayEquals(responseData.getBytes(StandardCharsets.UTF_8), decryptedResponse);
    }

    @Test
    public void generateTestVectorsApplicationScope() throws Exception {
        System.out.println("{\n  \"e2ee_test_vectors_application_scope\": [");
        for (int i = 0; i < 25; i++) {
            generateTestVectorForScope(EncryptorId.APPLICATION_SCOPE_GENERIC);
            if (i < 24) {
                System.out.println(",");
            } else {
                System.out.println();
            }
        }
        System.out.println("  ]\n}");
    }

    @Test
    public void generateTestVectorsActivationScope() throws Exception {
        System.out.println("{\n  \"e2ee_test_vectors_activation_scope\": [");
        for (int i = 0; i < 25; i++) {
            generateTestVectorForScope(EncryptorId.ACTIVATION_SCOPE_GENERIC);
            if (i < 24) {
                System.out.println(",");
            } else {
                System.out.println();
            }
        }
        System.out.println("  ]\n}");
    }

    private void generateTestVectorForScope(EncryptorId encryptorId) throws Exception {
        final String applicationKey = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(16));
        final String applicationSecret = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(16));
        final String temporaryKeyId = UUID.randomUUID().toString();
        final boolean activationScope = encryptorId == EncryptorId.ACTIVATION_SCOPE_GENERIC;
        final String activationId = activationScope ? UUID.randomUUID().toString() : null;

        final EncryptorParameters parameters = new EncryptorParameters("4.0", applicationKey, activationId, temporaryKeyId);
        final byte[] envelopeKeyBytes = deriveSecretKey().getEncoded();
        final byte[] sharedInfo2KeyBytes = activationScope ? KEY_GENERATOR.generateRandomSecretKey(32).getEncoded() : null;

        final EncryptorSecrets secrets = activationScope
                ? new AeadSecrets(envelopeKeyBytes, applicationSecret, sharedInfo2KeyBytes)
                : new AeadSecrets(envelopeKeyBytes, applicationSecret);
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> clientEncryptor =
                ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, parameters, secrets);
        clientEncryptor.configureSecrets(secrets);
        final ServerEncryptor<EncryptedRequest, EncryptedResponse> serverEncryptor =
                ENCRYPTOR_FACTORY.getServerEncryptor(encryptorId, parameters, secrets);
        serverEncryptor.configureSecrets(secrets);
        final String requestData = "test_request";
        final AeadEncryptedRequest encryptedRequest =
                (AeadEncryptedRequest) clientEncryptor.encryptRequest(requestData.getBytes(StandardCharsets.UTF_8));
        final byte[] decryptedRequest = serverEncryptor.decryptRequest(encryptedRequest);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedRequest);
        final String responseData = "test_response";
        final AeadEncryptedResponse encryptedResponse =
                (AeadEncryptedResponse) serverEncryptor.encryptResponse(responseData.getBytes(StandardCharsets.UTF_8));

        System.out.println("    {");
        System.out.println("      \"encryptorId\": \"" + encryptorId + "\",");
        System.out.println("      \"encryptorScope\": \"" + (activationScope ? "ACTIVATION_SCOPE" : "APPLICATION_SCOPE") + "\",");
        if (activationScope) {
            System.out.println("      \"activationId\": \"" + activationId + "\",");
        }
        System.out.println("      \"applicationKey\": \"" + applicationKey + "\",");
        System.out.println("      \"applicationSecret\": \"" + applicationSecret + "\",");
        System.out.println("      \"temporaryKeyId\": \"" + temporaryKeyId + "\",");
        System.out.println("      \"envelopeKey\": \"" + Base64.getEncoder().encodeToString(envelopeKeyBytes) + "\",");
        if (activationScope) {
            System.out.println("      \"sharedInfo2Key\": \"" + Base64.getEncoder().encodeToString(sharedInfo2KeyBytes) + "\",");
        }
        System.out.println("      \"requestData\": \"" + requestData + "\",");
        System.out.println("      \"timestampRequest\": \"" + encryptedRequest.getTimestamp() + "\",");
        System.out.println("      \"nonce\": \"" + encryptedRequest.getNonce() + "\",");
        System.out.println("      \"encryptedDataRequest\": \"" + encryptedRequest.getEncryptedData() + "\",");
        System.out.println("      \"responseData\": \"" + responseData + "\",");
        System.out.println("      \"timestampResponse\": \"" + encryptedResponse.getTimestamp() + "\",");
        System.out.println("      \"encryptedDataResponse\": \"" + encryptedResponse.getEncryptedData() + "\"");
        System.out.print("    }");
    }

    private SecretKey deriveSecretKey() throws GenericCryptoException {
        final SharedSecretHybrid sharedSecretHybrid = new SharedSecretHybrid();
        final RequestCryptogram request = sharedSecretHybrid.generateRequestCryptogram();
        final SharedSecretRequestHybrid clientRequest = (SharedSecretRequestHybrid) request.getSharedSecretRequest();
        final SharedSecretClientContextHybrid clientContext = (SharedSecretClientContextHybrid) request.getSharedSecretClientContext();
        final ResponseCryptogram serverResponse = sharedSecretHybrid.generateResponseCryptogram(clientRequest);
        return sharedSecretHybrid.computeSharedSecret(
                clientContext,
                (SharedSecretResponseHybrid) serverResponse.getSharedSecretResponse()
        );
    }

}
