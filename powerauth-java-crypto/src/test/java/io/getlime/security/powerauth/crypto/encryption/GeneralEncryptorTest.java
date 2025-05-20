/*
 * PowerAuth Crypto Library
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.crypto.encryption;

import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.RequestResponseValidator;
import io.getlime.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.*;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.AllArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import java.util.Base64;
import java.util.List;
import java.util.UUID;


import static org.junit.jupiter.api.Assertions.*;

/**
 * Test to validate functionality of high level {@link ServerEncryptor}
 * and {@link ClientEncryptor} classes.
 */
public class GeneralEncryptorTest {

    private final static EncryptorFactory encryptorFactory = new EncryptorFactory();
    private final static KeyGenerator keyGenerator = new KeyGenerator();
    private final static KeyConvertor keyConvertor = new KeyConvertor();

    private final static List<EncryptorId> encryptorIds = List.of(
            EncryptorId.APPLICATION_SCOPE_GENERIC,
            EncryptorId.ACTIVATION_SCOPE_GENERIC,
            EncryptorId.ACTIVATION_LAYER_2,
            EncryptorId.CREATE_TOKEN,
            EncryptorId.VAULT_UNLOCK,
            EncryptorId.UPGRADE,
            EncryptorId.CONFIRM_RECOVERY_CODE
    );

    @AllArgsConstructor
    private static class TestConfiguration {
        final String applicationKey;
        final String applicationSecret;
        final byte[] keyTransport;
        final String activationId;
        final KeyPair keyMasterServer;
        final KeyPair keyServer;
        final String tempKeyApplication;
        final String tempKeyActivation;
    }

    private TestConfiguration configuration;

    /**
     * Add crypto providers.
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Configure required cryptographic keys before the test.
     */
    @BeforeEach
    public void configureKeys() throws Exception {
        configuration = new TestConfiguration(
                Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16)),
                Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16)),
                keyGenerator.generateRandomBytes(16),
                UUID.randomUUID().toString(),
                keyGenerator.generateKeyPair(),
                keyGenerator.generateKeyPair(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString()
        );
    }

    // Generic tests

    interface DataValidator {
        /**
         * Validate whether request data looks OK.
         */
        void validateRequest(EncryptedRequest request) throws Exception;
        /**
         * Validate whether response data looks OK.
         */
        void validateResponse(EncryptedResponse response) throws Exception;
    }

    /**
     * Common test function for generic encryptor.
     * @param version Protocol version.
     * @param validator Request and response validation.
     * @throws Exception In case of failure.
     */
    void testGenericEncryptor(String version, DataValidator validator) throws Exception {
        for (EncryptorId encryptorId : encryptorIds) {
            testRegularEncryptDecryptWithConfigureSecrets(version, validator, encryptorId);
            testRegularEncryptDecryptWithKnownSecrets(version, validator, encryptorId);
            testEncryptDecryptWithExternalEncryptor(version, validator, encryptorId);
            testInvalidMacInRequest(version, validator, encryptorId);
            testInvalidMacInResponse(version, validator, encryptorId);
            testRequestResponseObjectValidation(version, encryptorId);
        };
    }

    /**
     * Function run one standard loop between server and client (e.g. encrypt request, decrypt request on server, encrypt response,
     * decrypt response on client). The client and server encryptors are constructed with no secrets; secrets are configured separately.
     * @param version Version of protocol.
     * @param dataValidator Request and response validator.
     * @param encryptorId Encryptor to use.
     * @throws Exception In case of failure.
     */
    void testRegularEncryptDecryptWithConfigureSecrets(String version, DataValidator dataValidator, EncryptorId encryptorId) throws Exception {
        final RequestResponseValidator validator = encryptorFactory.getRequestResponseValidator(version);
        final EncryptorParameters encryptorParameters = getParametersForEncryptor(encryptorId, version);
        // Create client encryptor
        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(encryptorId, encryptorParameters);
        assertFalse(clientEncryptor.canEncryptRequest());
        assertFalse(clientEncryptor.canDecryptResponse());
        // Apply secrets
        clientEncryptor.configureSecrets(getClientSecrets(encryptorId, version));
        assertTrue(clientEncryptor.canEncryptRequest());
        assertFalse(clientEncryptor.canDecryptResponse());
        // Encrypt request
        final byte[] requestDataOriginal = generateRandomData();
        final EncryptedRequest request = clientEncryptor.encryptRequest(requestDataOriginal);
        assertTrue(clientEncryptor.canEncryptRequest());
        assertTrue(clientEncryptor.canDecryptResponse());
        dataValidator.validateRequest(request);

        // Create server encryptor
        final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(encryptorId, encryptorParameters);
        assertFalse(serverEncryptor.canDecryptRequest());
        assertFalse(serverEncryptor.canEncryptResponse());
        // Apply secrets
        serverEncryptor.configureSecrets(getServerSecrets(encryptorId, version));
        assertTrue(serverEncryptor.canDecryptRequest());
        assertFalse(serverEncryptor.canEncryptResponse());
        // Decrypt request on server
        assertTrue(validator.validateEncryptedRequest(request));
        final byte[] requestDataDecrypted = serverEncryptor.decryptRequest(request);
        assertTrue(serverEncryptor.canDecryptRequest());
        assertTrue(serverEncryptor.canEncryptResponse());
        assertArrayEquals(requestDataOriginal, requestDataDecrypted);
        // Encrypt response
        final byte[] responseDataOriginal = generateRandomData();
        final EncryptedResponse response = serverEncryptor.encryptResponse(responseDataOriginal);
        assertTrue(serverEncryptor.canDecryptRequest());
        assertFalse(serverEncryptor.canEncryptResponse());
        dataValidator.validateResponse(response);

        // Decrypt response on client
        assertTrue(validator.validateEncryptedResponse(response));
        final byte[] responseDataDecrypted = clientEncryptor.decryptResponse(response);
        assertTrue(clientEncryptor.canEncryptRequest());
        assertFalse(clientEncryptor.canDecryptResponse());
        assertArrayEquals(responseDataOriginal, responseDataDecrypted);
    }

    /**
     * Function run one standard loop between server and client (e.g. encrypt request, decrypt request on server, encrypt response,
     * decrypt response on client). The client and server encryptors are constructed with known secrets.
     * @param version Version of protocol.
     * @param dataValidator Request and response validator.
     * @param encryptorId Encryptor to use.
     * @throws Exception In case of failure.
     */
    void testRegularEncryptDecryptWithKnownSecrets(String version, DataValidator dataValidator, EncryptorId encryptorId) throws Exception {
        final EncryptorParameters encryptorParameters = getParametersForEncryptor(encryptorId, version);
        // Create client encryptor
        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(encryptorId, encryptorParameters, getClientSecrets(encryptorId, version));
        assertTrue(clientEncryptor.canEncryptRequest());
        assertFalse(clientEncryptor.canDecryptResponse());
        // Encrypt request
        final byte[] requestDataOriginal = generateRandomData();
        final EncryptedRequest request = clientEncryptor.encryptRequest(requestDataOriginal);
        assertTrue(clientEncryptor.canEncryptRequest());
        assertTrue(clientEncryptor.canDecryptResponse());
        dataValidator.validateRequest(request);

        // Create server encryptor
        final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(encryptorId, encryptorParameters, getServerSecrets(encryptorId, version));
        assertTrue(serverEncryptor.canDecryptRequest());
        assertFalse(serverEncryptor.canEncryptResponse());
        // Decrypt request on server
        final byte[] requestDataDecrypted = serverEncryptor.decryptRequest(request);
        assertTrue(serverEncryptor.canDecryptRequest());
        assertTrue(serverEncryptor.canEncryptResponse());
        assertArrayEquals(requestDataOriginal, requestDataDecrypted);
        // Encrypt response
        final byte[] responseDataOriginal = generateRandomData();
        final EncryptedResponse response = serverEncryptor.encryptResponse(responseDataOriginal);
        assertTrue(serverEncryptor.canDecryptRequest());
        assertFalse(serverEncryptor.canEncryptResponse());
        dataValidator.validateResponse(response);

        // Decrypt response on client
        final byte[] responseDataDecrypted = clientEncryptor.decryptResponse(response);
        assertTrue(clientEncryptor.canEncryptRequest());
        assertFalse(clientEncryptor.canDecryptResponse());
        assertArrayEquals(responseDataOriginal, responseDataDecrypted);
    }

    /**
     * Function run one standard loop between server and client (e.g. encrypt request, decrypt request on server, encrypt response,
     * decrypt response on client). In this test the external encryptor is used on the server side to actual data decryption.
     * @param version Version of protocol.
     * @param dataValidator Request and response validator.
     * @param encryptorId Encryptor to use.
     * @throws Exception In case of failure.
     */
    void testEncryptDecryptWithExternalEncryptor(String version, DataValidator dataValidator, EncryptorId encryptorId) throws Exception {
        final EncryptorParameters encryptorParameters = getParametersForEncryptor(encryptorId, version);
        // Create client encryptor
        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(encryptorId, encryptorParameters, getClientSecrets(encryptorId, version));
        assertTrue(clientEncryptor.canEncryptRequest());
        assertFalse(clientEncryptor.canDecryptResponse());
        // Encrypt request
        final byte[] requestDataOriginal = generateRandomData();
        final EncryptedRequest request = clientEncryptor.encryptRequest(requestDataOriginal);
        assertTrue(clientEncryptor.canEncryptRequest());
        assertTrue(clientEncryptor.canDecryptResponse());
        dataValidator.validateRequest(request);

        // Create server encryptor
        final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(encryptorId, encryptorParameters, getServerSecrets(encryptorId, version));
        assertTrue(serverEncryptor.canDecryptRequest());
        assertFalse(serverEncryptor.canEncryptResponse());
        final EncryptorSecrets secretsForExternalEncryptor = serverEncryptor.calculateSecretsForExternalEncryptor(request);
        // The state of encryptor should not be changed.
        assertTrue(serverEncryptor.canDecryptRequest());
        assertFalse(serverEncryptor.canEncryptResponse());

        // Now create external encryptor
        final ServerEncryptor externalServerEncryptor = encryptorFactory.getServerEncryptor(encryptorId, encryptorParameters, secretsForExternalEncryptor);
        assertTrue(externalServerEncryptor.canDecryptRequest());
        assertFalse(externalServerEncryptor.canEncryptResponse());

        // Decrypt request on server
        final byte[] requestDataDecrypted = externalServerEncryptor.decryptRequest(request);
        assertTrue(externalServerEncryptor.canDecryptRequest());
        assertTrue(externalServerEncryptor.canEncryptResponse());
        assertArrayEquals(requestDataOriginal, requestDataDecrypted);
        // Encrypt response
        final byte[] responseDataOriginal = generateRandomData();
        final EncryptedResponse response = externalServerEncryptor.encryptResponse(responseDataOriginal);
        assertTrue(externalServerEncryptor.canDecryptRequest());
        assertFalse(externalServerEncryptor.canEncryptResponse());
        dataValidator.validateResponse(response);

        // Decrypt response on client
        final byte[] responseDataDecrypted = clientEncryptor.decryptResponse(response);
        assertTrue(clientEncryptor.canEncryptRequest());
        assertFalse(clientEncryptor.canDecryptResponse());
        assertArrayEquals(responseDataOriginal, responseDataDecrypted);
    }

    /**
     * Test whether we can catch invalid MAC in request.
     * @param version Version of protocol.
     * @param dataValidator Request and response validator.
     * @param encryptorId Encryptor to use.
     * @throws Exception In case of failure.
     */
    void testInvalidMacInRequest(String version, DataValidator dataValidator, EncryptorId encryptorId) throws Exception {
        final EncryptorParameters encryptorParameters = getParametersForEncryptor(encryptorId, version);
        // Create client encryptor
        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(encryptorId, encryptorParameters, getClientSecrets(encryptorId, version));
        assertTrue(clientEncryptor.canEncryptRequest());
        assertFalse(clientEncryptor.canDecryptResponse());
        // Encrypt request
        final byte[] requestDataOriginal = generateRandomData();
        final EncryptedRequest request = clientEncryptor.encryptRequest(requestDataOriginal);
        request.setMac(Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16)));
        assertTrue(clientEncryptor.canEncryptRequest());
        assertTrue(clientEncryptor.canDecryptResponse());
        dataValidator.validateRequest(request);

        // Create server encryptor
        final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(encryptorId, encryptorParameters, getServerSecrets(encryptorId, version));
        assertTrue(serverEncryptor.canDecryptRequest());
        assertFalse(serverEncryptor.canEncryptResponse());
        // Decrypt request on server
        try {
            serverEncryptor.decryptRequest(request);
            fail("Request should not be decrypted");
        } catch (EncryptorException exception) {
            System.out.println("!!! Invalid MAC correctly detected in request");
        }
    }

    /**
     * Test whether we can catch invalid MAC in response.
     * @param version Version of protocol.
     * @param dataValidator Request and response validator.
     * @param encryptorId Encryptor to use.
     * @throws Exception In case of failure.
     */
    void testInvalidMacInResponse(String version, DataValidator dataValidator, EncryptorId encryptorId) throws Exception {
        final EncryptorParameters encryptorParameters = getParametersForEncryptor(encryptorId, version);
        // Create client encryptor
        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(encryptorId, encryptorParameters, getClientSecrets(encryptorId, version));
        // Encrypt request
        final byte[] requestDataOriginal = generateRandomData();
        final EncryptedRequest request = clientEncryptor.encryptRequest(requestDataOriginal);
        dataValidator.validateRequest(request);

        // Create server encryptor
        final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(encryptorId, encryptorParameters, getServerSecrets(encryptorId, version));
        // Decrypt request on server
        serverEncryptor.decryptRequest(request);
        // Encrypt response
        final byte[] responseDataOriginal = generateRandomData();
        final EncryptedResponse response = serverEncryptor.encryptResponse(responseDataOriginal);
        response.setMac(Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16)));
        dataValidator.validateResponse(response);

        // Decrypt response on client
        try {
            clientEncryptor.decryptResponse(response);
            fail("Response should not be decrypted");
        } catch (EncryptorException exception) {
            System.out.println("!!! Invalid MAC correctly detected in response");
        }
    }

    /**
     * Function test whether RequestResponseValidator implementation works correctly.
     * @param version Protocol version to test.
     * @param encryptorId Encryptor identifier.
     * @throws Exception In case of failure.
     */
    void testRequestResponseObjectValidation(String version, EncryptorId encryptorId) throws Exception {
        final RequestResponseValidator validator = encryptorFactory.getRequestResponseValidator(version);
        final EncryptorParameters encryptorParameters = getParametersForEncryptor(encryptorId, version);
        // Create client encryptor
        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(encryptorId, encryptorParameters, getClientSecrets(encryptorId, version));
        final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(encryptorId, encryptorParameters, getServerSecrets(encryptorId, version));
        final EncryptedRequest validRequest = clientEncryptor.encryptRequest(new byte[0]);
        serverEncryptor.decryptRequest(validRequest);
        final EncryptedResponse validResponse = serverEncryptor.encryptResponse(new byte[0]);

        // Test for invalid requests

        assertTrue(validator.validateEncryptedRequest(validRequest));

        EncryptedRequest request = copyRequest(validRequest);
        request.setMac(null);
        assertFalse(validator.validateEncryptedRequest(request));
        request = copyRequest(validRequest);
        request.setEncryptedData(null);
        assertFalse(validator.validateEncryptedRequest(request));
        request = copyRequest(validRequest);
        request.setEphemeralPublicKey(null);
        assertFalse(validator.validateEncryptedRequest(request));

        if ("3.1".equals(version) || "3.2".equals(version) || "3.3".equals(version)) {
            request = copyRequest(validRequest);
            request.setNonce(null);
            assertFalse(validator.validateEncryptedRequest(request));
        }
        if ("3.2".equals(version) || "3.3".equals(version)) {
            request = copyRequest(validRequest);
            request.setTimestamp(null);
            assertFalse(validator.validateEncryptedRequest(request));
        }
        // Additional data in older protocols
        if ("3.0".equals(version)) {
            request = copyRequest(validRequest);
            request.setNonce("AAA");
            assertFalse(validator.validateEncryptedRequest(request));
            request = copyRequest(validRequest);
            request.setTimestamp(128L);
            assertFalse(validator.validateEncryptedRequest(request));
        }
        if ("3.1".equals(version)) {
            request = copyRequest(validRequest);
            request.setTimestamp(128L);
            assertFalse(validator.validateEncryptedRequest(request));
        }

        // Test for invalid responses

        assertTrue(validator.validateEncryptedResponse(validResponse));

        EncryptedResponse response = copyResponse(validResponse);
        response.setMac(null);
        assertFalse(validator.validateEncryptedResponse(response));
        response = copyResponse(validResponse);
        response.setEncryptedData(null);
        assertFalse(validator.validateEncryptedResponse(response));
        if ("3.2".equals(version) || "3.3".equals(version)) {
            response = copyResponse(validResponse);
            response.setTimestamp(null);
            assertFalse(validator.validateEncryptedResponse(response));
            response = copyResponse(validResponse);
            response.setNonce(null);
            assertFalse(validator.validateEncryptedResponse(response));
        }
        // Additional data in older protocols
        if ("3.0".equals(version) || "3.1".equals(version)) {
            response = copyResponse(validResponse);
            response.setNonce("AAA");
            assertFalse(validator.validateEncryptedResponse(response));
            response = copyResponse(validResponse);
            response.setTimestamp(123L);
            assertFalse(validator.validateEncryptedResponse(response));
        }
    }

    /**
     * Make new instance of encrypted response object with identical values copied from the provided object.
     * @param response Response object to copy.
     * @return Copy of provided response object.
     */
    private EncryptedResponse copyResponse(EncryptedResponse response) {
        return new EncryptedResponse(response.getEncryptedData(), response.getMac(), response.getNonce(), response.getTimestamp());
    }

    /**
     * Make new instance of encrypted request object with identical values copied from the provided object.
     * @param request Request object to copy.
     * @return Copy of provided request object.
     */
    private EncryptedRequest copyRequest(EncryptedRequest request) {
        return new EncryptedRequest(request.getTemporaryKeyId(), request.getEphemeralPublicKey(), request.getEncryptedData(), request.getMac(), request.getNonce(), request.getTimestamp());
    }

    /**
     * Test general encrypt-decrypt routines with using protocol 3.0.
     * @throws Exception In case of failure.
     */
    @Test
    public void testEncryptDecryptV30() throws Exception {
        testGenericEncryptor("3.0", new DataValidator() {
            @Override
            public void validateRequest(EncryptedRequest request) throws Exception {
                assertNotNull(request);
                assertNull(request.getTemporaryKeyId());
                assertNotNull(request.getEphemeralPublicKey());
                assertNotNull(request.getEncryptedData());
                assertNotNull(request.getMac());
                assertNull(request.getNonce());
                assertNull(request.getTimestamp());
            }

            @Override
            public void validateResponse(EncryptedResponse response) throws Exception {
                assertNotNull(response);
                assertNotNull(response.getEncryptedData());
                assertNotNull(response.getMac());
                assertNull(response.getNonce());
                assertNull(response.getTimestamp());
            }
        });
    }

    /**
     * Test general encrypt-decrypt routines with using protocol 3.1
     * @throws Exception In case of failure.
     */
    @Test
    public void testEncryptDecryptV31() throws Exception {
        testGenericEncryptor("3.1", new DataValidator() {
            @Override
            public void validateRequest(EncryptedRequest request) throws Exception {
                assertNotNull(request);
                assertNull(request.getTemporaryKeyId());
                assertNotNull(request.getEphemeralPublicKey());
                assertNotNull(request.getEncryptedData());
                assertNotNull(request.getMac());
                assertNotNull(request.getNonce());
                assertNull(request.getTimestamp());
            }

            @Override
            public void validateResponse(EncryptedResponse response) throws Exception {
                assertNotNull(response);
                assertNotNull(response.getEncryptedData());
                assertNotNull(response.getMac());
                assertNull(response.getNonce());
                assertNull(response.getTimestamp());
            }
        });
    }

    /**
     * Test general encrypt-decrypt routines with using protocol 3.2.
     * @throws Exception In case of failure.
     */
    @Test
    public void testEncryptDecryptV32() throws Exception {
        testGenericEncryptor("3.2", new DataValidator() {
            @Override
            public void validateRequest(EncryptedRequest request) throws Exception {
                assertNotNull(request);
                assertNull(request.getTemporaryKeyId());
                assertNotNull(request.getEphemeralPublicKey());
                assertNotNull(request.getEncryptedData());
                assertNotNull(request.getMac());
                assertNotNull(request.getNonce());
                assertNotNull(request.getTimestamp());
            }

            @Override
            public void validateResponse(EncryptedResponse response) throws Exception {
                assertNotNull(response);
                assertNotNull(response.getEncryptedData());
                assertNotNull(response.getMac());
                assertNotNull(response.getNonce());
                assertNotNull(response.getTimestamp());
            }
        });
    }

    /**
     * Test general encrypt-decrypt routines with using protocol 3.3.
     * @throws Exception In case of failure.
     */
    @Test
    public void testEncryptDecryptV33() throws Exception {
        testGenericEncryptor("3.3", new DataValidator() {
            @Override
            public void validateRequest(EncryptedRequest request) throws Exception {
                assertNotNull(request);
                assertNotNull(request.getTemporaryKeyId());
                assertNotNull(request.getEphemeralPublicKey());
                assertNotNull(request.getEncryptedData());
                assertNotNull(request.getMac());
                assertNotNull(request.getNonce());
                assertNotNull(request.getTimestamp());
            }

            @Override
            public void validateResponse(EncryptedResponse response) throws Exception {
                assertNotNull(response);
                assertNotNull(response.getEncryptedData());
                assertNotNull(response.getMac());
                assertNotNull(response.getNonce());
                assertNotNull(response.getTimestamp());
            }
        });
    }

    // Tests against mobile SDK vectors

    /**
     * Test encryptor with using test vectors generated by PowerAuth Mobile SDK (iOS). The protocol version is fixed to 3.2.
     * @throws Exception In case of failure.
     */
    @Test
    public void testVectors_3_2() throws Exception {
        // Paste vectors here (generated by iOS unit tests)
        // ----------------------------

        // Shared constants
        final PrivateKey masterServerPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode("0UWBQVv5sVJhKWV5JHX+d8t8qO55Cv7C0LTyB0Kj7H8=")));
        final PublicKey masterServerPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("Ah7lqT0/foYC6eCUZtoiPFOycQBa2imdNE0HfvtGwaWk"));
        final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode("+f07IdgNmrBjmk0uvkQ1LkMA3MPZAHvutdq/mw7xWp4=")));
        final PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("AiK5Ka6zZNvH0NAKB9H1eoGBLX48QmUz7eUPj9xzZDaf"));
        final String activationId = "036CC14B-E4F8-4B01-A825-5129832ACDDB";
        final String applicationKey = "lceX5qe+O+Sb0t8TQqg35A==";
        final String applicationSecret = "m3JdVJMIu65fXXFi4VqjjA==";
        final byte[] transportKey = Base64.getDecoder().decode("kqeu5p9hTJCRRIL6Z3ZuqA==");
        // Original request data
        final byte[][] plainRequestData = {
                Base64.getDecoder().decode("PyZF8EKo90xFEIpTJGuL6uQVx6VyE62o2y3iAI0hkFH5WrSKuLDiLSlBdc1bSNJhiX2Iupe7XVtR6WUjl3ja5auSo+1CSjw22TZTJSnraKyC2Y7P5NdXX1ydO8l6DvH8XClIsMmxN0NKhU1jv80YLMotnqg="),
                Base64.getDecoder().decode("HDZYhY7BswRNaz+kWNRe44+wJDxFaoygdrmfB1TH37yrKRxU"),
                Base64.getDecoder().decode("NrkCKPoy0KSYy6BBSjnUFqY+a4N7mg89v5qAGn0jMV0rvBVjDpC1f6CpDW/9BdbSNeFDhsn6BhI16IkjDT6Q8gjHLQcphOR3CLH5nXmtIJh3iA=="),
                Base64.getDecoder().decode("xLXAyu+7E2cm"),
                Base64.getDecoder().decode("PD0kxR+y/Qxz9aKe6ELkV78="),
                Base64.getDecoder().decode("AThxBRaaFKKJbuZ7v3LTQYIuqrbiLVz3QWFRTiGU6KK3Cqr2p4Ea4ju2wdrpiF8VDfLhdQ/zGfaj5TYGRURAx49kw8r/NuFbHFWc6z5Nz18HeItC++tfudOBE3qdfd7kgISA4Qut+vZDjw9NBcxkeg=="),
                Base64.getDecoder().decode("vgoWJjf9JsVwt5valonsmUbKWNigad5IPnXT/OfEaWPQ78gF6O9472r4OzkTKNPQYmXun+R9epCfjZPEqqiDlZlPGLEPUYYTLgUeR2XlI8DGChBhbWPSZI6Ugwyd+X3Ro2w0VwHqm6U="),
                Base64.getDecoder().decode("ekKYoHUzjn1mTMdyr8FjHHMrn7g8RbHIg8U96ZXm+13oRsH/i9cXfjui7wtOGD9iOBrUU/K3Tt3R4S4M8ltJ1HUs8JBWDIwFnsKW08vNNdA40W0wPAJxgwNqFIkU/U4P"),
                Base64.getDecoder().decode("AUXZK/yMIz499r4hH7LOxyVZUfkayI6JO58ZRm+ogjhE8wpsIC46m8Cv0Vk/mdMT4GptjtacHMSV8KBeaPfvtSvLAhVuaVdh2/dI"),
                Base64.getDecoder().decode("mCEVFpjmoVOUcymairmXbZ7F+EkVT8vSNSENdxRGoK7Np3I3BkqTxzYWIYrEcjLE0HggHeBBGgpN3H2Dp/jGBTgiYpRS"),
                Base64.getDecoder().decode("MRslr4vEEEqxHLYqFuObzVkI4IBhcGkDfRdmy13KzS9iJO7D11XlADmqEssBlz4QnHFAh/kP4pvVT37sGoSJ6qtrsUT2IOmJPRjCYKkBKoE5oDpIpQyF+gmQ7j51wVbVuUw="),
                Base64.getDecoder().decode("1do2gvR5EfaBJyjJvH1SmfpAuURNX1cJz6O4CjS/fFH5NeoEvSUSxAW+HcVRUzjesx9Pa3k="),
                Base64.getDecoder().decode("Z/z9HTTMEsrB4CkAKTe7WG1bZ6nyrYjU7mI="),
                Base64.getDecoder().decode("kqJI7eaR"),
                Base64.getDecoder().decode("QfLUmc8aalHnOIdTAyvkSrN3SevHhZOQrG1121032T/lrA=="),
                Base64.getDecoder().decode("d2c8IYfurWBv098GawTPIL8uAcqBz3EWPXp5yjGLX0PLU5oH6iE8BAfqo+pdD7NGBw=="),
        };
        // Original response data
        final byte[][] plainResponseData = {
                Base64.getDecoder().decode("ZX74GcevJC9M683Oo4g2hxBbBVInpedTZyDvvMhBhlp4RI8xiJImSbHeYjKR+69YtQjej9Llnm22Sfw="),
                Base64.getDecoder().decode("FLRp3SfS0YrXzRytpW9cFw=="),
                Base64.getDecoder().decode("evLfjrto"),
                Base64.getDecoder().decode("lhrPrbiUiQoydmb9tBfZoUNzRZ5Wl0xki7ULmWQmC0M3qpxSypGfn4isfBVl"),
                Base64.getDecoder().decode("evMUiGvfLfjjUvHzLXC5qCQW9tgCKGqt8AbroYd2mSb8xVrXoxd7k01NDtihyyyuTlMxSy7VNqf1z7wM4Zw7W7K0nU7azkmdxET0i7toD1DQUrcyP4/Abnl0pfUqk2K8PcOd1iUFhbUi67lEfsQq6YbfradVi34="),
                Base64.getDecoder().decode("HsnsnBC+N82xfkO46+PiDWzhoRufRzh59JN4bOA="),
                Base64.getDecoder().decode("9HfVv0VqE17EupyWGlgttqo7gUp4VjeBGKkUNE/nkkZQN69z5YE2a88L804TjHRuL4+kwLQzDO9g"),
                Base64.getDecoder().decode("vT3kacynb6mchKh0eltMtETOAiipgGknLJSRzGdfrLHSwNH2PMlwZpUluofzu2lJ+KyCgwnq6OW3osnYoQPvr8CpjZwH2Aych9xV19faL+Fr8I7usuM/3Gj5Vqbl7Rnisj7XwYuTK1u+n4TV8DEr"),
                Base64.getDecoder().decode("x4kw5XrYEkYiTA8ZuatClZyoYhpXEqGQ3lSYQ9TgMp2JXpd9prHI9nRgfL8EumiaD50RvihBrYKLLt6UNnVr9BJV2suGBQGQx3lstXL07Zy1yTKGbgmEFeVYsWcZg03Xvli8pWTfVrld8reSGxQ="),
                Base64.getDecoder().decode("umWWeeSu6MARxC9ens7ZS+gPaW31aMUsachmqBJWBfezMeRTUAQELxq2aSdGsZeGUF8sQwXOOt2hzcXh+2CFVzEA/KEppRSTdYWEZwcI1srMhWK5F5gZDP/PKppOZf/Y9KDj1ajI2BhpAlFvEMUF"),
                Base64.getDecoder().decode("XcdjVOTzbr5XJnCIPoTCNDuvoW3EPv3/dKxlT2O+JpjIF299bdOurU962XZwZxhKb3sih+gunRbRgLCFOpCn/l9Ns3ixYd5I7KGkJSrxE8K7hqw4V20b+qZdfUCho5B38Pbn7ITYMS1yraDLnGCd"),
                Base64.getDecoder().decode("kQ+I2V3qgG/i6/Z6TXh3ruz0sk+6cGNqZX+DAqu8TD6glLi9x8HD6WqFsf3fDnbrlWXobU+7zhzCNB2YQIAYSP1nKhaYi/A6SlvAkbxc4W9+LTUu1la1Arb9cYdqHzKNXUZ4f4hkQpQGoEfvCTTqwzITfHxyn6cLSllj5nZlK0U="),
                Base64.getDecoder().decode("TI9WMf+xw9SBRFR2XfNdCsoC"),
                Base64.getDecoder().decode("QwPihJJ9FttnQMM98n3hKF1zU/T7gZ7uN9zxnGO9lqtZTHbsrkSFpmEFwiSStk8yINZSGjmMIW8rtqOv2J1ihJeJpF0BJaXD3VR7mNk0Zg8HJO9C0SpmbW/ASeET9LhOB0WgW8+x5J+r+Krbqg=="),
                Base64.getDecoder().decode("jL4KoKtOATckhTpEJ0UKBByXHFV5r0Y3jfydkV1i+GYfaD0+wKo5l/z0ToQlqBRsqMV7LA=="),
                Base64.getDecoder().decode("Xv3f3dfp/hpF2USDCADoORMVNhwTzu0ID/30UK9dfkJlP+GFJ1ZrOInKiLckyce33CeYBDUYU5YYEnzpBMLZEU2IaUdPhFSnlINSKw2DfjgYm1i7LHekSVGxCR3k64RKHUtCLwDsEL3QRiE6ZVEKPi3FDg=="),
        };
        // EncryptorIds
        final EncryptorId[] encryptorIds = {
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_LAYER_2,
                EncryptorId.UPGRADE,
                EncryptorId.VAULT_UNLOCK,
                EncryptorId.CREATE_TOKEN,
                EncryptorId.CONFIRM_RECOVERY_CODE,
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_LAYER_2,
                EncryptorId.UPGRADE,
                EncryptorId.VAULT_UNLOCK,
                EncryptorId.CREATE_TOKEN,
                EncryptorId.CONFIRM_RECOVERY_CODE,
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_SCOPE_GENERIC,
        };
        // Associated data
        final byte[][] associatedData = {
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhsY2VYNXFlK08rU2IwdDhUUXFnMzVBPT0AAAAkMDM2Q0MxNEItRTRGOC00QjAxLUE4MjUtNTEyOTgzMkFDRERC"),
        };
        // Envelope keys
        final byte[][] envelopeKeys = {
                Base64.getDecoder().decode("8BNzgMiTO9ELURm77VQD/72TCN3Cf6TlQWp57wUfe4boH2baIQ2z2eqqpWs6P+24"),
                Base64.getDecoder().decode("wFdoVzNTn3tRElimPDuheWSYGbh+kG0NTEF08fkhMvMm8+Nsc4TnYWhCQYx12l0d"),
                Base64.getDecoder().decode("smZ9wr2s80pA6n2xCUALKuuCjIU8/bTW2X+bW8o2iXeq0D5rQVRSSszfqaX+YJ1Q"),
                Base64.getDecoder().decode("/OB2HgA2ZmsBx2AUQifDxIs91LraUt5TciHtgKYYwI3/Nd/svUY8VrAN5Qg5cn9P"),
                Base64.getDecoder().decode("Y4Yde9z91lhdqsOYfALJT7LuB1VBDHhXL68bYa5Ia3onLy8PVLUKBm3+lGz1Si08"),
                Base64.getDecoder().decode("BC+IYb9PlXskecV5pHZhv/vdlHa3YfwE4kZ/g0dO26W2/+bSI+LUOhZQr3xe/Yy7"),
                Base64.getDecoder().decode("KfA0L0rOp7CYFJbWIslmU7ZnRHPYcZqnxT6WIqoqo3z211kWDmXfZjl1Ppji73aN"),
                Base64.getDecoder().decode("hlSE7oddA9IUKuT+S/5+GJlN35i1fdZ8q8UXFVJr1b9Y0CTkMZyV85DDqnP/PQLI"),
                Base64.getDecoder().decode("24bk9iBebrq2bTpY7x7kjZpA28xj5+IDn1+YmKEWKY6S4tRngOVsjX3yy9M0l4pW"),
                Base64.getDecoder().decode("IxqrAPtP7jKfEUfADFS7XaOdg6chPr2mRof1Dz7mKTrjPYpTNaChY/28qzagHytv"),
                Base64.getDecoder().decode("y3GCO2K/VeWLF1EBrfhmlx6Wuf+GeSssjnWyTT522wuBHWb0vsZCuP78pIbAAas6"),
                Base64.getDecoder().decode("ujybVXEbKeU3M0WTk4Zb5rwDuWzDKTWBjAqZa6LMMzdZGhdl1lXfvl5W+PWc8m4R"),
                Base64.getDecoder().decode("v0Vj+eDF5U3dhrfUYo+LVp5qa966gNdfwrlGArrgi/X3QKCRCiu2qkggSg3BiiKX"),
                Base64.getDecoder().decode("8Se8sHPrASl83j/5BLHJeY8sHhwfJ6DLME1PXropkQClWoxkIV2J0o89y0Q1DO8O"),
                Base64.getDecoder().decode("O7XcnEXwVYxBHP8ooQ5wBQ3/RWp813XuAL/nPsz7SuBAqTyKEc42HJax7BiTC2Fc"),
                Base64.getDecoder().decode("RhijpnRtB71Pa3Okf0Suw4El/XhkaQ8nwopwRuqeFGp1K1qoI0OrMNQrLe2c73df"),
        };
        // Requests
        final EncryptedRequest[] encryptedRequest = {
                new EncryptedRequest(
                        null,
                        "Avlav7hfDwCA1zJq6gyczWtUn+MhNCebikIH7rkUkoHB",
                        "jZ1y4ZkJpvRTDHFXQ+J9jsWaFuV0AvqpUXFDCi3bH90YCutTufSamKXpEIhFfqBmhzYak2g6LBUfgmTJ7c74D+eOqGRn1EwZOcgVHKbaFjgthwSUnD8E7maEK9u5qmVdi52drt9vQ1Cye5jWn0vSTKmvSkfcQcmK42o/0r/8LXs=",
                        "ovJWPbaRr/+9nDLwHhej1u9iNVg0OVVNNO2zI88AM9g=",
                        "BKIsGcbgqAqEKhuEJFX25Q==",
                        1691762307382L
                ),
                new EncryptedRequest(
                        null,
                        "A97NlW0JPLJfpG0AUvaRHRGSHh+quZu+u0c+yxsK7Xji",
                        "qYLONkDWFpXefTKPbaKTA/PWdRYH5pk9uvGjUqSYbeK7Q0aOohK2MknTyviyNuSp",
                        "DNlZdsM1wgH8v2mAROjj3vmQu4DI4ZJnuTBzQMrHsew=",
                        "ZQxUjy/hSRyJ3xBtqyXBeQ==",
                        1691762307384L
                ),
                new EncryptedRequest(
                        null,
                        "AtSsPjiwbh3GnWYjCOejGIGg0LEbl1X6SY4f1F77PG2I",
                        "px6h9Hu+wyH38YySO6istbinaF3ALyrBraad0qhTCJZrYrVlTv1bEnfvElBupQzGUx3SikSqaOjR+UKzj9TVfa2rw36LkSIVFZYk1gG6xW3U852ZvJpuTtw6h7WhFYks",
                        "bySXBDU/9mDx9T8i9DFWX7Xn4O6HZK2EMLpA+ogv3eM=",
                        "6p2OQ20Ezjd+RcCAr2w34w==",
                        1691762307384L
                ),
                new EncryptedRequest(
                        null,
                        "AnjhcBNyzpyUs8TnvW164zfwVk6UQjof8zueumjUADlB",
                        "rQDj9EseF9GvJY6a0YCExA==",
                        "Mpu0lek/SXf7JvxnlEngv/Bx8nFhxi54vHVrBr0f7H8=",
                        "0qdMsQVKjhE8gwRm8It2Vg==",
                        1691762307385L
                ),
                new EncryptedRequest(
                        null,
                        "Aqa/2aW4VuZTXaFoc0rcc67RotG0rbiqpvontLsdoLIe",
                        "ic3LxIfwgK9XbckAxivYvMdwuAL9nOC/Kdry4w/1xRw=",
                        "OyQcPCU8opsBN88vCE/9Km53a8sNqamIMIwxNfOOyto=",
                        "6YzESLD7x6ANSxeirDAXZQ==",
                        1691762307385L
                ),
                new EncryptedRequest(
                        null,
                        "Aomhgt+8zAMsuRYgsVJMioFFPLP6eK+4omcLfftS/PHK",
                        "xNdtHsq28x+cFGxLGJbW6l7SscETdLRHejmXYETzU8670YyaqpiGOO5276vb3XDnxM6GjKHEztXruz8YBQzWKYqc6YVU4WqKMNHBu1A/9yKY8KGE+XsSxyrkZxoIM4oZuUp7p1ui+H87PPY8Vs/c9dMM5YUMYVUFZA1kBnzskKs=",
                        "z05w9DN9CKWtURAr0g7D5Kya8Jvp+CQFLNz2Fy1inaI=",
                        "fWn7lYWXckz72X4elEU+3g==",
                        1691762307385L
                ),
                new EncryptedRequest(
                        null,
                        "AoCXG9cbmKBSPP2zi3pOuJQV6dENZ751dUhEGoDqLWVB",
                        "fqsJXWuIt2rwwsWLu8TbPnCxwha6PTGTpzmsLq/Tdynt5YcrEBk9wlRaQIXzWi0KbES20BjJbgL7JIaY2qj/XlFU+vxB+vybUnHrtpe2NaDthaYgdEecX3W1uzpyd745ogDSGe19gOqwXCFCRFLF+w==",
                        "T/tx0z+61zPosCa2Y0oJBepFOOfn0O1lrMKkr9RSVNY=",
                        "YQwJfuPmImzyBhGqZ7QMNw==",
                        1691762307386L
                ),
                new EncryptedRequest(
                        null,
                        "A/5KJP3Cb8DhNjo8Cs2juYLwpswsUBJe6XXdwowIelP7",
                        "wUXXg0vgkZjqvqIfJm7YPgk+7bwgWSttizi+uSKAE4z8dOY8zUp0uvsvsUqDIvnhisnc82IyS/kGhSg1QWyzjAdfr5rWehl+aS+e8GPIu3Ok8n0qNG9TJ1n/UxuD6Ok/WTCHsRW2QoU2I8vB6BAMUw==",
                        "J88D9JrcVVmVlUNe5g6IzEHd3m+PqfSzBNyCfEb+UXg=",
                        "vr95iaeHXK4W0o0WU3MAkQ==",
                        1691762307386L
                ),
                new EncryptedRequest(
                        null,
                        "A3TP+jPFrRgQd563V8goh2wJgvRS9eMpwjo9tOivLboN",
                        "8MjZ4+3cUC7IkwyNK09WSDMOrMpNwfHrXUM3A/19sjyOVZJIAl9HYJySlN8h9A2qrG7l0Eu6nFUwjDH8+NHfqBHCdOAnpncwgANE5GetzgA=",
                        "pmWeeMSroONdztB05rb6932llfAJJo6+uqLvwYq01dw=",
                        "ecQuWdjhJB90a0vxXJCHDA==",
                        1691762307386L
                ),
                new EncryptedRequest(
                        null,
                        "A0w7WTl0Q3vhxlyKJWV1hM1YC484mysCqhjay9uFSmvG",
                        "K0Ep8dWNhD99yZm/mShFy53DYbTCntm582rlWwskPfcKTE7b/7gBFbXaGly1o9cmQ9Wv9RjBx8Ai4rda/KKbyMq3ZaX6ljAWFpOmqUIgMUQ=",
                        "Zr7vEn6WBYkFFZRAvq3UdRR/OWF2uOK0ABik9fytOUo=",
                        "20zLGrzcBPr6aPWQTOESuQ==",
                        1691762307387L
                ),
                new EncryptedRequest(
                        null,
                        "A4o3ZVufjyXvJnc98rvHxTbQgCpY1dwMkJs4mKkT78up",
                        "8hYJGXgHLD8tH9sFrRlU6fxGWU/JdlSBpPkL178OFRdORMXTY/ReMRbajQD3bXKzXjmhdYR5X13fHsmiuvHIQVPRFB0ZyS43HT/uEDpWh8SWByKjNB5je6ftEySsmpKGp0KvmjXgiIRX7TiRzwJ03g==",
                        "VX9TB4hPM7/6U/NQvBNR6VaP1loyq2ZhcmEu4NWCU7g=",
                        "Z5XV6HOqZ3ftaxEkdgjIwQ==",
                        1691762307387L
                ),
                new EncryptedRequest(
                        null,
                        "AhVR4QxfHA5resv8ppMANxzZwkaWphsmtA/EENi8Swjp",
                        "ASC8xiBSyjx8wGwf71U9Zk4nZT9w//8AafiZaT+9RtObUmb1HjguWv3Xpqejnf5kml3Z7sXDYgFemFYLklhL5A==",
                        "8wlb+Pz3UulREpbcBV4GfiY4bePugBPV6ywgaycvrpU=",
                        "Y6DDsiZb40xV1lhNNWloiw==",
                        1691762307387L
                ),
                new EncryptedRequest(
                        null,
                        "A9ok7XXLWWWtQAxERdvFv3I31D+pgZuY3cVSbjpJHLda",
                        "+b0Ki6WcoaoGJhBrGR28zeMqS91XMmCCtO/HU3xaKNg=",
                        "jmkaGcZ+qnrMXtD1R7YhRmJJU+d3y6/nATjNno7DA0A=",
                        "MrgNNwmotGQZspWUFNMuRw==",
                        1691762307388L
                ),
                new EncryptedRequest(
                        null,
                        "A24fQipKuaW7sOmXbpZDW+QetW/aBmS+2fkrkSdNDlQe",
                        "GaXg6TBM+H4ru/E25gvV0g==",
                        "xV19DEuOG+SGpT22GU55mVQqU4I7/+vgWNFKDq6tK5k=",
                        "mXHJkh/NUVzxLAXRH2r+9g==",
                        1691762307388L
                ),
                new EncryptedRequest(
                        null,
                        "ArzfJWjDZrjndvQg3aFxZme6w/Z5P4uV4mBClCbURJuv",
                        "cbG2zh4dp5Ig65/Gdz97ZLm1vWeLfSUbIIoLWQXQm5pUVLkHJ55Mrl4TwdK6kTG0",
                        "lawZCFwh0NTpNafMwC92/ndMnkryG4yxfAvp/4q1F3Y=",
                        "C48N0ekaenicTtsb6LEf1g==",
                        1691762307388L
                ),
                new EncryptedRequest(
                        null,
                        "At3TEHVJmtO+VPUtJ/ijXYhx1BAnjcDnQRk9AbhukeWa",
                        "4RPt1tswWfapZNWU7gFkuMyUADjsykdAQHQsMXHmghDE3l7dVYiMctKuj8RHFLAIsgI09toZelMAPRE1PLJz6g==",
                        "JgkwHwwwoDb14zokbecDQeqmOrJxRO0Lddv1sQp0bnQ=",
                        "fBHetJ5Z4ecTdnfJ9dD+Gg==",
                        1691762307389L
                ),
        };
        // Responses
        final EncryptedResponse[] encryptedResponse = {
                new EncryptedResponse(
                        "6gIBzx28iqPFxtI/UjSLnR8FoFB6xFyshfMsCzOShY/5FN6rcKLtkD2r9M0ihKKW2bviC4HmLUJWXZtDUog9LA==",
                        "/giQrgL3pX+ziYaWBgLCLUiPH/D5/f31A5lRxVA12sI=",
                        "kpgl9EC9+4KiKsUFlwLidw==",
                        1691762307384L
                ),
                new EncryptedResponse(
                        "UH04USDgyi9P36PtmGh7jNuAu7PbdayXnDEomzWiRQI=",
                        "4p++jQ7Ym3D3CwMBCs2+bOIfWfAF+aPZtuym48+5zsI=",
                        "rMhUf8cP0LS0r2WFFupW4A==",
                        1691762307384L
                ),
                new EncryptedResponse(
                        "o82fufbAJinoRVKiMlAY9w==",
                        "ayU0uzZ7tTyc8Us4AR+nZcQ8ubAY8AslpSnJXtWLoIA=",
                        "TlXLxl3QzkvMiJcNPKqETw==",
                        1691762307385L
                ),
                new EncryptedResponse(
                        "kKtNt76jdmC8ooSTxVhxl4Gm1eahP3tn3I5F4qE+rFv1vCgSfTP+BZq15mAtmPxX",
                        "4OCRqhwFd3ZzxOAYatNSW99FmehINKYl/u551IW+Li0=",
                        "Z7e1oAU+54be5c/UVd0I9A==",
                        1691762307385L
                ),
                new EncryptedResponse(
                        "VQLfGVujKbLbjYDdiXHnc4nqOPo5IQO00o2IpJRuHOQylW5dciR52EFrPVNXiQL17rDVVMmldeGRzilbB938zb8t9QIpYyJsfdI8bTd4fNJrU274CZKjeW9bi0pZrSJ+KmgVW1Ie7oMJ0Nw/m6blUCxQHDdoQgL6ogTPY21GBRo=",
                        "3srmFyVru0ah43aoyuro1Ra0AZhPVZ/IRYrHLF+BaYg=",
                        "sN703PpZgrNxMEtyLqmUSA==",
                        1691762307385L
                ),
                new EncryptedResponse(
                        "inCo5hDW9vy5b1/dFlxry8u5pSiKaTkewUeRudCRfp0=",
                        "SDeDv9TObKgyW1NgDmeBc4mTESWJfJReqPYiJLaO1i4=",
                        "V1EHs3fAn+E32kqp1MxwCg==",
                        1691762307386L
                ),
                new EncryptedResponse(
                        "E0KBXTsjEB99tGzGNU6kijZArOQDA4XvoTscux6tefnSafXlHNpeAnORj59GaavEjWhNOoj65Ydd5/0LUUJhFw==",
                        "D/k+OwZ1EgEAfF7Slj8FpShAWHn2Ki8RRdA7wC41Fks=",
                        "2ilRIrI23/eJnUMeEcQg4Q==",
                        1691762307386L
                ),
                new EncryptedResponse(
                        "yDq2+CANxqAlj9q1oG2hcOdHt72TCmQuufa3BS8GBNBZNb1xqBhZoTzDXmdmcdbSXKepUVxj6UFRCT9J3wSNQIKImwBVdPzkHTgdBW/Gc82lGgkSzQvCmAmLKOkSLJkVqB7az2JtEo7WsdB+GABViw==",
                        "LZMF/pM5g7o67AkDca2uHRDAXzhVf+FUmXhTXZAbOXM=",
                        "0ci+hsMP8mBYlsF5lJKvLg==",
                        1691762307386L
                ),
                new EncryptedResponse(
                        "BTtWJFMupEQ4GlaFyEcaLi23YE8eZqDs+ZxQPz7suEDH691kchGJhfs10CqIPyyXlDGkOyAQT4cTRJHknbx6XongqOSyBImNaCW9UyS7+AE6mLK1YVcQFCppzd/YB5Zh0xGI9CbLI72O9FYZHGRGtQ==",
                        "08iGPB0MCqEpej4sh5CzKfAt8ktutN8ajeivkpushCo=",
                        "IKhsARWx99rpf/IoN16XbQ==",
                        1691762307387L
                ),
                new EncryptedResponse(
                        "YGOcH+UPrtD6xL5wkSW9M5W5HPQgTT5qCapbC1rOH4k9Cv1sDpnMjCT4ePn2K1j80YyxU0KHuQJB/R7Rz/iUbNmnV8Ri+mvCjv5OthkD+P5vcWxUfeg1LCX5KLBROjPkbRejxO91+VmQiwy+gjBWoQ==",
                        "3oraw0O9CgIfTHJ4h08xEzVxHlLOXxjz9kajjaBp/7Q=",
                        "ucp8o29LdMCJd+1L1ulLAg==",
                        1691762307387L
                ),
                new EncryptedResponse(
                        "FcwUzp8ee8of47XNQjQKDz9DjpzofDn6chMLiX7UvZaJn++hEpDfIN/v03qSKIOZiNf4cI1fgiC5WoSXDLXfZSjivJGLOiXzYW+TqGCkcr/DZzoo0/GvXH01/F3h7q5GhdDy+QH2TmKinz6Bbebziw==",
                        "ZE7JejfCs6hryHPg2OD1wl89kjt4wqxaTjuUoXueSI4=",
                        "5kv5XPhqzNxkbwlVSzwgBw==",
                        1691762307387L
                ),
                new EncryptedResponse(
                        "QaVyHX4/Du7d6P9shxPgPhoerLYy7/Bj6iFMRbx2aIw/vU+E7n3tX07nEiM7r8hPdu2Y1jUmfpHUnorUqXRPMzsLdGz1Dcqy47p/JcVW0+sEKFOpT52r6BhNE4iU7lP1brVSjbhpiqCKf11H5HSZdCNKX+T/Sf21SftqP+UAQp44Lt84PPsszsRyOA6Vyntk",
                        "AWG6XZCD9cdNyAeRdKI3yiAaCnIbDkyCzOy/0Zro/Gg=",
                        "/vdhJZpeQ65k+rengkK1AA==",
                        1691762307388L
                ),
                new EncryptedResponse(
                        "TxtxLvVlfQLBVIdc7E3S80I6hGdyhyVKGCtkv4pHnK8=",
                        "+en3LYRIkol8rMBBs0iV4WWsZoIfH8oVkNzg1Opyonk=",
                        "wLczqR8MsNZfwR1zk3cwBw==",
                        1691762307388L
                ),
                new EncryptedResponse(
                        "rl/7v8+OtJ/Z9Sw14ixX6wmAHGDjfTcvqhc/7d08I1/0YhShhtMjY2tYfKZJMC2CgSr6sCUv6bWY0kAAZkkVroV6szQhfI30UMn+Oko20IU01VxCRQlmD3aOS6cD9xA7Qtz/uTZCOAbkZTXOUDPg+w==",
                        "hfPwRknzNUnULYgVEEfEKFbd8jdC7zPxc2DU8wC9ZnE=",
                        "/170WhIMeUiQ1D3jOkHTdA==",
                        1691762307388L
                ),
                new EncryptedResponse(
                        "kRkbsDXXR27W9Ynvdwxm01rD609uAFXQTIRDthBNocZNkD/I9Own07JmzB6Zky7+4GupZokobr2UL6qyVSmZMg==",
                        "Jw/tdkpvAjxYyWs5/srIw/f+ge4at68Vi4sBx4GWGec=",
                        "VmdUQZcFRbKM5YzOGETrDQ==",
                        1691762307389L
                ),
                new EncryptedResponse(
                        "3eIJBI864mTpLRDe+6EjBTyePGi90pZLBp2uDwKRfIi1gIzNUUEsyVvUCfVDlWpIhwmcBzrGQlfQe2yEY6srUuhuHyoMD1j/obos7TYnvgkWZ+UdC1kdaV6V+U28/OjnaLAZ+Wq7uOS3XwX7Ij+7uHRo9Mmasc+ULaX4i1lN1nE=",
                        "FQ5EZ3ns2GezvF+XgeLtzSPhrDNcopl8KK2DbtWTOtY=",
                        "RCSutPa+2dpHNyI1hCquYA==",
                        1691762307389L
                ),
        };
        // ----------------------------
        // Start of test

        for (int i = 0; i < encryptedRequest.length; i++) {
            // Prepare values for this batch
            final EncryptedRequest request = encryptedRequest[i];
            final EncryptedResponse response = encryptedResponse[i];
            final EncryptorId eid = encryptorIds[i];
            final EncryptorScope scope = eid.scope();
            final byte[] sharedInfo1 = eid.getEciesSharedInfo1("3.2");
            final byte[] appSecret = applicationSecret.getBytes(StandardCharsets.UTF_8);
            final byte[] envelopeKey = envelopeKeys[i];

            // Construct Server's encryptor
            final ServerEncryptor serverEncryptor;
            if (scope == EncryptorScope.APPLICATION_SCOPE) {
                serverEncryptor = encryptorFactory.getServerEncryptor(eid,
                        new EncryptorParameters("3.2", applicationKey, null, null),
                        new ServerEncryptorSecrets(masterServerPrivateKey, applicationSecret)
                );
            } else {
                serverEncryptor = encryptorFactory.getServerEncryptor(eid,
                        new EncryptorParameters("3.2", applicationKey, activationId, null),
                        new ServerEncryptorSecrets(serverPrivateKey, applicationSecret, transportKey)
                );
            }
            // Decrypt request and compare to the expected value.
            final byte[] decryptedRequestData = serverEncryptor.decryptRequest(request);
            assertArrayEquals(plainRequestData[i], decryptedRequestData);
        }
    }

    /**
     * Test encryptor with using test vectors generated by PowerAuth Mobile SDK (iOS). The protocol version is fixed to 3.3.
     * @throws Exception In case of failure.
     */
    @Test
    public void testVectors_3_3() throws Exception {
        // Paste vectors here (generated by iOS unit tests)
        // ----------------------------

        // Shared constants
        final PrivateKey masterServerPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode("oG1PJWwflQ8XRt4Nf4uzyBf0w0D4jNW22JxfImj4i5w=")));
        final PublicKey masterServerPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("Au12Pbz70flr9eizmYC72P3vPp/h2KWlmvcvfssF6xBt"));
        final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode("98pEwpFj60r8REpXzrflb5kzgj1aoxg1YEuKb0Kuwyk=")));
        final PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("AjG7M9W9qNUOu51dJROO4NE+xOnqppxxyFU1Tn3FhXui"));
        final String tempKeyIdApplication = "D3D82A6B-47CF-4225-BBE5-BAD96FB84CA4";
        final String tempKeyIdActivation = "1221CD15-9092-4779-A157-04DC229A63F7";
        final String activationId = "CF2E9A48-9085-4AA3-8F85-FFAFD2380609";
        final String applicationKey = "WQBeNgCHGlW58rzUlP7Ehg==";
        final String applicationSecret = "Epbv1D+tibvvkqGIyDOT5g==";
        final byte[] transportKey = Base64.getDecoder().decode("EsOk4R701klML5Ljd07Y5Q==");
        // Original request data
        final byte[][] plainRequestData = {
                Base64.getDecoder().decode("f+jScpA8qs2OAR2TWqnDD6W00yUYsdIGuE1nCsqKvVBDfedwA6XBHy4z/ey3"),
                Base64.getDecoder().decode("5jM1pRKPJpkv16zg9A5ZcEY3KXGr3p2de1hWZVsVKXL7PIzljrl2Lxg3RfWuf9myS17OBu7d2nO7SD1Sl3U2KtJA3+B1c202TqdQEXRT"),
                Base64.getDecoder().decode("K6cp8f5FyfsE3kv2HJubaJ9b5ILXAMc="),
                Base64.getDecoder().decode("5p4zk5/DaPiw2oFP0LSygOJD/VDGEfPQMcI1JO1iSqO4XYUr0yeKciDFxQ5r9Ji8C8ETJKD1/5hlJGURXw=="),
                Base64.getDecoder().decode("jC7527ZbuLU3ddoeSHOaE2f93sqL9IKyf9pjoIpU/6h0DowFlVmMibIyKWnL2dkDmKeIGFhh4EzvEcAnk7b5bU9Jv7ItenE3bxDu55NQXQs2XjZLqwb+gdjt6f2dZx6s3K/1+hG8zv2QYc1y5Ielnus="),
                Base64.getDecoder().decode("17e8s/ckRIR52A964Vb/AXZ/Gcv4yT1RCS42ZUiwegzk"),
                Base64.getDecoder().decode("6KNE7ibjx5Hx6OOeVl6FcvHBueCvds5nzUE2CBgJ/15chbQQM+Qghg02so06AgaDHEIdyuiA8wREEwHSDDwUsDbYbSZGsJcXFWZmtIutzbTsL08zg9HsjgtWc+I7IX3n6T286Q=="),
                Base64.getDecoder().decode("OhwnzC44O5E8bplAyUT+HjAoJ5nuaXxpZryl17DHSmHFBRjejBznYYHCl2UUDYTpgT00j8Fvu+GtS3i9jr704r/z5XENGsb5aqitVERSiPQDWXHSeF5w/L45U535NzjJCv9gudDSXrPaP2mB"),
                Base64.getDecoder().decode("EsSeJzVFi30Ph7KGBamnpavP2IVJQyXSyh3AR/YX5w9hRVsT7dEqVrCvP7WSRX5X9HCvQU3aqqB/OLVGMF8B81o08p/7WExeaf1PylcbRqomHwqBgO64LdAXa80="),
                Base64.getDecoder().decode("PNhn+JpA6ivlcZXpYBM9SJgAqrGUJ1Fs422sJDJyHqPFmBaZOlyYQGM3hSexgNtU47iQyiz+qfdslFNszKiCohV1fx0C6nmH4xn96333ISVx7i8YmM+SI06LWfdb"),
                Base64.getDecoder().decode("w/kWbwDE27WzyTzi/SNm7a4V7MGZaShVR9LaSaj+y0nT/6CBfdk/4POlqyXpJD31D+mL7c8z2dOFyktHNJccliODZI0="),
                Base64.getDecoder().decode("QHMC/ZEQ0A1uEQtslxYtaeBCI4R8cklIjOThRuCykszKHq5cnYjARUIFLiHzDfClIwZIxaRY7qm4etYWiwzxv9pEI2y08dtWfeywaroWFUPJI+Zr5/1S79fDleYx2QYqxZnBFVogSNgg7A9eOxRtv99/u96atw=="),
                Base64.getDecoder().decode("oHXR8sAoeoo+o9RzysQqiZeYkQffKDf5ab+RZNyrF9jax+eVEIhA6uOrZ784aw8CnzKqqJNRW352T1l7JbliEhhtTllzqjY3g3KMGI+vEg=="),
                Base64.getDecoder().decode("rpPcobnE/XGR56rklurFfgyiGO2EMwhlM3a6rNo1DjTZcsCFGXW2e01c7T03RlkdJhihJwCwRFIA1shW6RdCi/mE1KF9X0g8Z3i5e9acegsjeL1i3xcgXUzh8j3dntsrh1N6SsY="),
                Base64.getDecoder().decode("tW44GiuzI4cYlPRuRk9xSzQBkISv1BS+vIvZMGufm3acrE9w0QoUgzt1YZV0kHRVJy1+smchfK42"),
                Base64.getDecoder().decode("GxTDg2vEtfGvOdhRbZI5b08gE/YL1uEk0dAYBgbmf4cywD6t0ItWtaJgTTK1OC4YAztf1WxCyG8="),
        };
        // Original response data
        final byte[][] plainResponseData = {
                Base64.getDecoder().decode("Q0o+ObtisXK/MO/0W+DggFD6cnlhUrSCHocN3Mu1IYrFgxswSk2VELlCF3U7OzPwFS1g3vcwxTYdjCGyyAcVECODy68Dd2Tv0vLlDfYjB5D8+E75BCrYhwRbh3W3OaC0VxI8V3xh125mFx0PWRXJuxf1yKB3rtY="),
                Base64.getDecoder().decode("6UfrYjWYCkBIK9Ori7qB1KEfWwz5DYGVaKYxcz8OLWpfO8xtON8xa4a9ORaTRCKbKYMHh6zloo5/Zn7bZ8YmguicAmWB1gqqwtUDyYtTMwAjyXLmKs2shftLQYtauUSkWNc="),
                Base64.getDecoder().decode("GMHLlB1cZzelL0+5/JUOVnUzI44eN54zxA=="),
                Base64.getDecoder().decode("qYTFk6IaB2B3roQRjIyzAzegiRSgVpPmjifyQQ7e+fWKwm8="),
                Base64.getDecoder().decode("Cl0eRW9Aq7auie9qaXpYsWbES2fNmbqRM6U2sxU="),
                Base64.getDecoder().decode("vhdJ0uPZVyeVEdxSo3ErO2Dogay5oL7b/cL/BRhellDBq8X67puO+50fgOAgfL0bpQMZBZh/uLgxBrGf2bVOzTpO8R6WOYxjg0FnOdb91/VbGSvTncwbX71U"),
                Base64.getDecoder().decode("/QKbpOxjKicszPmiM6HjPejXRYwfVJowveYeCwYMSFb4vDP4P0jJCLqsCIAVQwzqMs0DcVjBMQgaaE9an7z+sVQ0M15xYgRqdg=="),
                Base64.getDecoder().decode("x/WlUGQzvMB1zu64EYtpzq8="),
                Base64.getDecoder().decode("k0+sImOGUwOb/1s8U1uI5uZ8gZaszNuU4pKWq2d775m/iAUB7f0o6kVnfDzZZvEXfEzXlKZsdzf2bE/5KJ1q2WsMhxwlbPCZ+zWzhD3lPMueXK7Sas8EOQ=="),
                Base64.getDecoder().decode("qxljpcx47/22kqbxnjZhbDq6tL8nWJp9fcR/bN7/dh64rsLxeT2mQdQAdhUw8bMbUlv113sco8bI+Y0z/R4ZWlDThcLus6WZOyizKEVipIZzAteUmWww"),
                Base64.getDecoder().decode("AMC6x6qz309wM6mbk85poct0k18dW4Xg0TyzqNRMOrNxdESxgdt+X7uqINrGGT80uaDuk8K5BXgd6vIGn0cnPkiW"),
                Base64.getDecoder().decode("zZZA"),
                Base64.getDecoder().decode("F6aVUJhxIkRBjsyPk1yH"),
                Base64.getDecoder().decode("Pkl94I9MOlQmYJEXBhu0EtRPygUtB7a3GP6+uaXCu6wAF8Ky9pjUKPNvtmLtR1v1Svspml7W3EjeEWXc2Zk6bEjN6x4+Jh7ilR2c5QZOySRv72c="),
                Base64.getDecoder().decode("Ggd98d/1vIPsmJqV2yry1je2eXYrHUQNiGFATp6JoKJX2w=="),
                Base64.getDecoder().decode("EKHnpKeG7l8q+Q9go+QZzJVV3+mcYNWmjC9wqzoipDje6tz3yarhobMvuZhXHN3Kx9keC0V30QE="),
        };
        // EncryptorIds
        final EncryptorId[] encryptorIds = {
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_LAYER_2,
                EncryptorId.UPGRADE,
                EncryptorId.VAULT_UNLOCK,
                EncryptorId.CREATE_TOKEN,
                EncryptorId.CONFIRM_RECOVERY_CODE,
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_LAYER_2,
                EncryptorId.UPGRADE,
                EncryptorId.VAULT_UNLOCK,
                EncryptorId.CREATE_TOKEN,
                EncryptorId.CONFIRM_RECOVERY_CODE,
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                EncryptorId.ACTIVATION_SCOPE_GENERIC,
        };
        // Associated data
        final byte[][] associatedData = {
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkRDNEODJBNkItNDdDRi00MjI1LUJCRTUtQkFEOTZGQjg0Q0E0"),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkRDNEODJBNkItNDdDRi00MjI1LUJCRTUtQkFEOTZGQjg0Q0E0"),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkRDNEODJBNkItNDdDRi00MjI1LUJCRTUtQkFEOTZGQjg0Q0E0"),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkRDNEODJBNkItNDdDRi00MjI1LUJCRTUtQkFEOTZGQjg0Q0E0"),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkRDNEODJBNkItNDdDRi00MjI1LUJCRTUtQkFEOTZGQjg0Q0E0"),
                Base64.getDecoder().decode("AAAAAzMuMwAAABhXUUJlTmdDSEdsVzU4cnpVbFA3RWhnPT0AAAAkQ0YyRTlBNDgtOTA4NS00QUEzLThGODUtRkZBRkQyMzgwNjA5AAAAJDEyMjFDRDE1LTkwOTItNDc3OS1BMTU3LTA0REMyMjlBNjNGNw=="),
        };
        // Envelope keys
        final byte[][] envelopeKeys = {
                Base64.getDecoder().decode("k074hGF+oBZMhhh6BS6CY+4/aaN5TrIwDsVEwn/WjyXWgNSqshjiANmOR36L/Shc"),
                Base64.getDecoder().decode("ocMfq8QlGi+/5e/xilUCZUxqh1Z4PqZmmNgmDnm1BLZbFZuh8pFvx28zAo8moHkz"),
                Base64.getDecoder().decode("XSS+JT0S8o2fXPArZZ/MY+9MqExJV5pG1lCrSJwzlY/i5irGdshKl5PN2h8mChNm"),
                Base64.getDecoder().decode("8FIKg1R4BQFtlANmy0f27fWQaINgL9vlr3hLym/xt1MQ3bofjwVIYqu7wGiJD43n"),
                Base64.getDecoder().decode("OaRGAw2XdkzsHzcUXj8l/uglAVVFtuzMjvR9+5+kTFIz+9SP4KDXJwugYEZ3sL6u"),
                Base64.getDecoder().decode("JBm52ZtwKYBBxV7Ar5Wtf4Y9OTDv9OU2pFEv7WJYA74yMJRQcALWugqV79CG5Aqf"),
                Base64.getDecoder().decode("2YtkBfXRrhUffeu98I38CCfdkR33/8c+C82j52YSIlwJ5KcauOk47WXjOczOkFsg"),
                Base64.getDecoder().decode("LpfRIkzTWQYF4458Wxx3qEUvwBpRKugRHQdaC9bBp0jtkdPpRXCQKSXO8xCjZUIx"),
                Base64.getDecoder().decode("eP8jZvzxPBOv7E+w39z2JsGJEXNskfxQgPV8R0X4aY9nlgyESMa8A5fbrAgh70QY"),
                Base64.getDecoder().decode("kScXW3XPZF8vQzwAPs1H1kH8V7nT1TRXHpYRKI8LrnZ37VEtToEKizwxAW8YV67A"),
                Base64.getDecoder().decode("1jpx3WEzDxbt2hjfTY/3rEbVTuhZagFLxhZne9l3N17jJov2hrOd2Vc8tJfKDGXC"),
                Base64.getDecoder().decode("A0sds7ZIaPKsR10Q7ai/E/Y8grHSbS4WYKck4zLVEdkejcDwXpAvRfUcxg7bw+fm"),
                Base64.getDecoder().decode("u1wtm4Ll21Y5FkSF9lbURDcuz425PK6HOSKWoMgUZMeMjwvBtJIdkXmtuaeaISpL"),
                Base64.getDecoder().decode("l4lJ2fBE+21MU0L1impmrXOVMXw4d6CpoSLS5Wp66kojeR94cEdUg3JAgkcKyClA"),
                Base64.getDecoder().decode("nxPNGpOegXx9wNc4blM250eyYKY+zZ2DGf3Zfp9irTZ7jpzcEO7fb5BAx1YnbTed"),
                Base64.getDecoder().decode("7en0qGieNCkyZGT44+/pQbgebgoVWk9527ygAFOy6s3s1+XY/kiOXm6fp9ru/y9r"),
        };
        // Requests
        final EncryptedRequest[] encryptedRequest = {
                new EncryptedRequest(
                        "D3D82A6B-47CF-4225-BBE5-BAD96FB84CA4",
                        "AjpBEi1V6hxMt6SXmn6pFuSNd6S2loTKwqa/9A5hL+lh",
                        "7m3Eh0RUc2S4k1sThtVQvwzK1QEiAJwxAgKmTigAqY3wPen5EO+HJG6FolSVTM0J",
                        "un7Wreqd91tQp1UuqrKDRwKpCIHn4dxFaD6PEay94tQ=",
                        "yss0YBlx0ERypDj/4HF6oQ==",
                        1723109505418L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "AjJv5HtX/WOk2ajL186KJ+9GGbYYAsx/kEAcSr7Aot0k",
                        "/n1ijWx8rY0a9DSd8peAMbEznhyKhSGPDbmRQWwTzLErKdyFCSWMdsfyYjprK/MmYczAoJvSgHhe9FeWvg/aMpGWsykjlaGzprZ/WZT+vMA=",
                        "jkQZgeHwm2UVgCX3EU/SpBLZcDCoWCqke7PnZgXtz4Y=",
                        "lGvXPH17WpDErd277D7w1w==",
                        1723109505420L
                ),
                new EncryptedRequest(
                        "D3D82A6B-47CF-4225-BBE5-BAD96FB84CA4",
                        "AgGQFxV3lw5VDbHHI6lTdoUOMvA+ciXc+JFI8OsY4ErK",
                        "Kb0IVdVE5aicv70QY6cfDnE690jVhEqhOct28y1r7G0=",
                        "mbyD0Z341x6pkXNwhA8Q8DQzP9Pk6E3CkYxJ+7pAauA=",
                        "L9wCRvnLTUkla7IAlrprEQ==",
                        1723109505420L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "AgjDJvBgQubjJsc3mG/usmz1Saachm56h+L7Ao+ODS+G",
                        "OnI4x+FwViNe3zACnpkhLib5U8s37EKPYlcp7+EP+0R9EYYkEfQoosyavXMvcULam0TvdixhIt98xWsW6UPrDA==",
                        "o123KQc+4MLuxG1rlfS/uFVTsChp1mIrwokpIsXeGRE=",
                        "dYXDUMkh3AcATXwenSdDyg==",
                        1723109505421L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "Aos8e2W2DbLD+rBNA6Mwzj+RWaETuLGo4M/sEdRtRENL",
                        "z2qMMLBv9dEqvv9SdZpxdoUmvPKBTlQU5MELLivW+2SZyv4cK+yT46cLEM8bdnly1f28/3nYogZaajzftXbZM2Bj8cSYBjZuQRLIbUcjz2wLtWP7BYEAk8LlS+gA3dAOrZ/lWI4MOEt1lgG0JkEHBkEpmD2s3wPSNr9t1fUJqU4=",
                        "bqA6SQkCfOVf5+5Bt1p6cj5PheYjeGMOb5ynF3oW2Jc=",
                        "C0t960Q62hxHaWnnu6sYEw==",
                        1723109505421L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "A1Ph49CFAdWfQFlzYPDeaFdipYMJGY+qYWEJgphvE601",
                        "v5chxkMsHJanOOw/av+oRbPsk2Va226igxQ+2frT3AraTLwJxotHocnTFxyK7pNk",
                        "0yjA3GDiKJooZMi2hOkkD+aICpY7Slo/nzg0oTYrqJM=",
                        "EoNe/DqID0Isa15tzFeTYw==",
                        1723109505421L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "A+5Y+goYEAPxnM5xVxLkZoJTSG5SEoa2D6U2/a//+vgS",
                        "gg9w0km2aG+pchUeHL5BEjDMROOcuTmDSMTBRRf9OyTwrYA6+a991jhdZiSYT6MSK52n2hd6yWvEp18NQI6VOy0gsxAzoOXfYf2Rir9rvtIcmtRC76cYDqLHA9Dl2TyrzacnOSZJRwGOePal1RM8vQ==",
                        "T9Y0jFGSzIsZ0YWmSZ3D4JpDP8W18ksPMIb0obUAUiM=",
                        "nt9/rGJ74UoCKT24QS+USw==",
                        1723109505422L
                ),
                new EncryptedRequest(
                        "D3D82A6B-47CF-4225-BBE5-BAD96FB84CA4",
                        "A7MzuALkFpmLMUOoPfXyx+aCAKZqP0V1RnRLNKbqrCdn",
                        "xaMGsBQgJ5NihO8GGrjG1epaEszSDcv8Z67WBJy0olQ5sfrlx+nR112JAKIKqpDo4DApF9EOkDfi5za0DnlryvGPpiaLbngbF06QR85DFNkOUD5Gt/DuN/qbGdHYJ66AsZhAdUf8L0u5OGYbYF6ULQ==",
                        "hkLthp5Eti8L/EMksBU5eeJSpxAUHVZ9X/59ROyo3uE=",
                        "af7JpUq2cwR0Ekodu6WQQQ==",
                        1723109505422L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "AyAZz2budSXg9tUr41qMRIWZYHvf8ZRg1Ky1xXfjUVzP",
                        "P1E456VYswsieUXDxi49WldA647JbSy5YfwS6xoJijWZ7/ml3Zx5VMJYz+X8X9Wm2+GNiyWiLURpJaTMK3lwXOEFUWUDoP0cv6du+Vz7jQgoyPvgSxpcOeb9NEiOcbgc",
                        "MrFSFDaBZA1sDibSzT9Si+4blDj7q5Op33FfnYFwlzo=",
                        "o4KfZWSYNqBjwaHqJcwYTg==",
                        1723109505422L
                ),
                new EncryptedRequest(
                        "D3D82A6B-47CF-4225-BBE5-BAD96FB84CA4",
                        "A6tOYHM9zg9O4v/rTAiduPRfJgWLT47V/1SKVpOVfb3h",
                        "6E5yo1+y/Nv9A9uTr2dWijEAoOMOlCX39fdCDE5ohbBw6slMbFBIC6HUn7qBs8dBgMNJTatJEp/twGJZyaT6+WMOZRI7ec7/bOImrN9kjwkYq70gY/UHPETUyBkczYc+",
                        "1j6ULk0WucfGFjiN9T7oGykuh0BriYv3Y0y/FK7X+hw=",
                        "/KUGtLbpCgqW+KyTfP/1FQ==",
                        1723109505423L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "Ajqbv+0CUuWHZQuiU1d+Z8x4sbXDB37sm0Kbjp95kzPI",
                        "OKr4ceWyBbLTxzZhv5RQvlG44K+n+ohw4JUbV30lC0KIypNl0uKwdzSQtK5eljKXdfYxaLSuY+Gwj/NK+xdQkdMXskLeXluey5GET23HaL4=",
                        "048mD+C38ojf0M0CpEU/uLuZbRLlZVFfzCCK/2f0+KI=",
                        "K+XqUGF5lUKgTz0yaJ9p2g==",
                        1723109505423L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "A3uO4rYlQByC4ch5ylQEgFwOqYVANPLPw61DzbmT2nwH",
                        "VnYlfhQVaYFkCCvG6snx6bgGbHbNqS69AnBvcJ7o+vVtqtaZ13XaXWHCM3cyKW70QZs5uGuI/NWHD9pItXQpaxGkogmlixNc/EOpk7FJv04x1+SqKDFDveZgeORIFcOqX10V9BmhoqoBodUQ/Mf/19zc3/hXL6B2Py9MwnBlfxE=",
                        "YerKe/F5zFLkK52ebcwpcMxf3ZAmnGO+hWgBYk863UU=",
                        "HadtUun2ZzG8yY9ZdoMieg==",
                        1723109505423L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "Arn/DbG8zpduSRv5WazPO14rRicFGzzSruSeK91TzLcz",
                        "Hy6BkHDntqmbV56oNTL+7aIJloEtkiZkiDZOmaxtsZQPGh2ZOcdL58M29mX0SCJ5uWEIKiQMGARtRNef4K9/ZyiKV3VdJFkzXKKs3ul5d+w=",
                        "5hu/DaxE7c74Pv0abvafGTi1pET/2zUaOA6QDAaRlMY=",
                        "z6lNafKqRONRBYwT6mfZHQ==",
                        1723109505424L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "A2dQMe2lT6PNXju5qnY58dc7MrVlfeMxvmHpYZVSo1iy",
                        "yFi4XJ0kADIbf6xL4pShHhsAdDhmLyiHuf2uDVmGTsQDeDunVLn9E/cPOY3Pi8beTfyLMTuJs/KCYacDXkniCmzuawsftmASF14Ee2nLfUZoBhdA2HUDdKiIy+zvfrSChRx9YP0gkXE5bMRFpWgLmQ==",
                        "+MHylKbS+wVabW1ASOTyrVgHiSYtD7QeIP/mjWG0U8c=",
                        "xei7+wZwpJnRVnhsjRAEpg==",
                        1723109505424L
                ),
                new EncryptedRequest(
                        "D3D82A6B-47CF-4225-BBE5-BAD96FB84CA4",
                        "Ai7rf1nkviyd/H4oLwjazip5ceScgTyV+B3F/GqQblen",
                        "ZYxobd3H7Uj1VUQQvlh+7PBBzmtCPoVKDde5rjRbHx+10WRCFjV5Uhb3ySHWLuXUrqDmTGERRDEmPNXcfkp9Sw==",
                        "34Xcv3x1DVaNAsDnRyBCKynDmSVgzSaI3tAWWRKU1gs=",
                        "34OaEzc8gcHw/TDsr5hI+A==",
                        1723109505424L
                ),
                new EncryptedRequest(
                        "1221CD15-9092-4779-A157-04DC229A63F7",
                        "Awe+CP/SBxK4U8Szk4/2mJEI+k5J0t1Iul1FTNBNdG4K",
                        "Im5FJi42sIoKKuRQwyKaX/nGsRWDeDXNpE6jTyXmKENm/ulBftYmWCsDhX8uJKSi3ICtN70JtbNdOcWG+KsVAw==",
                        "kfqKaModZjh98LCMNOHyVdu2jr+zqIjq8Y185iTz9Qw=",
                        "5YS/q6v60vqPzZwW/TqOhg==",
                        1723109505425L
                ),
        };
        // Responses
        final EncryptedResponse[] encryptedResponse = {
                new EncryptedResponse(
                        "VKUZve03Rc+8N2D2YzGeX9ZZteeQws9ZAW7N2VVZ4cj8YHpHf+X4ULpqYeGKCHfJXi4Dvt6ZbbAU4i7rImvmRH7ZdMZgyVMlsRXwyJxIhDgkr8zLQlJDJ3Nc/TL2n2YTw3ukL2vv3ZW65UcDOWi9OBnXuEFYvuAjGR7zJLDL8Z0=",
                        "ebBjC2k7LndYqgOgbE239Rc1yhhRRhOGL/QGk23P458=",
                        "mrL2R2ochtK1QFfLi9dX3Q==",
                        1723109505420L
                ),
                new EncryptedResponse(
                        "qxbAsh4KlTWrfoRb2f65FUkBMfvPjJdPkc5z44rdNJ7angP/q83NTw19XurQ8N1RjA06ozqnOR4pr9KrjuWq38kyVEWEsrMsrE2rLjzcVqyoFNOBd3tPK74f/uLmbVFnqbUoKaqjn4mBIHCfgWle7g==",
                        "GMeP0BM62NDRxWBtHMsadAHQQzsgmfZfGU3x9piipfM=",
                        "beYoMVodt06E7yk2WMFiCA==",
                        1723109505420L
                ),
                new EncryptedResponse(
                        "l+Yl3JfRpcr+ReXSDdTo2GVbe+c98rpfX3vODqnrpkk=",
                        "cRPSf7+3IA8M1zjQnGEixuFlJ5O6hsmzvWeB2xFHfCI=",
                        "qPtFVgDgtgJpNTzuElDoVA==",
                        1723109505421L
                ),
                new EncryptedResponse(
                        "Y8KAD1G9wUpoTXpA0UKMI4PaUgS43uUFrOTBR3cCoBUdOWS4HizPdF+3SxdkbP5Z",
                        "QfQzM+0z0re6/AWMNOI8uP7syAeCtud+TkDt+H1X/tM=",
                        "A/+VbdsF+0s8HvJrBAtBCQ==",
                        1723109505421L
                ),
                new EncryptedResponse(
                        "+Jqs/d97p0Qau9ixhL23cctRnUwowZuTzvA3MHsBH24=",
                        "AgBS0dF5RSfPlvbqgtFpMwj2QSDQUXIUcZdNUyJPzO0=",
                        "iu0blftcv9NCHb0mJVqRKA==",
                        1723109505421L
                ),
                new EncryptedResponse(
                        "jKg+rY99pZ3gZa+h5Dfy7ohbhKKUIhKWltXrx8Az4DTyRiT8PfljuUKWD1nXYtpToAodYrI83scJ5OuoOILcxQ7/h3fLHs6KB642xaoV/od4eVMYoXqDXMraMojCsxCJ",
                        "8YJ8n79aFpOAawRnSfG7XlNYNdGVfP2iGKhrE2VP0ho=",
                        "qD/LMXJEWu8/64ZVLs3+7g==",
                        1723109505422L
                ),
                new EncryptedResponse(
                        "Od0g66R5gHPqyLjaKYkiSyKg11qzpMERanBS3qlSJ13MIArCWQWgq54408xvo1hpt5V8Wgj7ITwfsJ8+AQTZOgx7Wz3a1x56x8X7ooZhIk8=",
                        "ndfN2p7RMwWo6JDS4ifa5kleEW8CcBjjwySh67niVZo=",
                        "vywPr8XZ8b2YyDtHMikmfg==",
                        1723109505422L
                ),
                new EncryptedResponse(
                        "3GGQRP4u4+w/d7/KtPS8SjDa8lV7AxZhXbJKzKWwx80=",
                        "irvrHy2xNLjDfAeL/4dxmmSCuuDsOxXHCc95P/i/35E=",
                        "BMWmr4DsI8+WImCDvwB2/w==",
                        1723109505422L
                ),
                new EncryptedResponse(
                        "tfMDn6+5V1Zppc4huevk3LI/dgzOuSRTYqtXJf+xB/hNzNc2hChinWIjKMh2cdWwoms3WO+boaKGnCDdVbSCDEx+nFg6T4iN6rfz4qTwaov6KdLkT04Y8hnkbi4YAyNm",
                        "90Vud5c9q8Xy+UgMGtq5D6vPs5Hsn0Nkmj+rUmuUcz8=",
                        "YNJifcT945fhcKm3aqkhag==",
                        1723109505423L
                ),
                new EncryptedResponse(
                        "0fWvysKeg3naheL/A5cJjTiA+BmhZYbDkHVK63JPosXDhqZzqPrJ0/KvPE116ELpG2FzQP5LnD0Jk9eJ627p67nMhJD+jQkRFQgqKeggViiw+zEsQtp/dcIN3ZpdR+zh",
                        "TIe67QK7kYFlMI7tEMB5+DdqwVdAUNbje/xVyrLEwwI=",
                        "LdNF+2cVBklgSNtd8VgVHQ==",
                        1723109505423L
                ),
                new EncryptedResponse(
                        "WKwK5/O9ebjhrec16gMbS5tuAiYSE7/7oxMRc+DU8ZU6FSNUewK8O0cVOV3sT6++6U3QgPJLbgRIBP6lZjvAUcrzXlwjNjQJEmO3816BOo8=",
                        "Eo0IFaMj5O9ZPfq5DCqS+6m0swuEGgoVfihAKtDTnsg=",
                        "miiZTny2CvOrBZkjD+eaLA==",
                        1723109505423L
                ),
                new EncryptedResponse(
                        "jDmIvPflnOKjS45+cSCqaA==",
                        "h39gAppf4ooZoh3DlXUTg8K6hMvTeUDXjJIbrbEKefg=",
                        "G68hARhQVl/NlWqvqdrHAw==",
                        1723109505424L
                ),
                new EncryptedResponse(
                        "JCeEIhe8hUKPbb0+FB/s1A==",
                        "1ZYXTaUXg8BH37PHNUYZC/qAaiu72vvbBUMMayO5ygc=",
                        "v4k9JUEQqmqs0avfakFRiQ==",
                        1723109505424L
                ),
                new EncryptedResponse(
                        "lYITkSdxBpjIKd6YsORWZLKE21G3bbRSd+7/7CeSk0jXrtAnoyqvYfvcdx2TVtOVOlM8yAkgwuDn610ovcDW9mT5/HfvdoB1c7v8uwXwSEorpajFTT/b6tYo4fRD+lGt",
                        "8/r/tlMCzmHLwszOGUwBGGK9MM1Jis2R8Gmk4e17AJo=",
                        "WGeBG1GE8gFWSXQCUR9dKQ==",
                        1723109505424L
                ),
                new EncryptedResponse(
                        "it9d1VO49uCf4G3zax9Z0IxNmTaoUb2aVHZB45b8rmd/myB8pjEhvzowwatdx5fX",
                        "EmyVIkCwUqH0SCRxqHWDXIjZhB23uaxLFozdlzB8f7U=",
                        "XAqO+IzvrQ6zsEyHQd2pyg==",
                        1723109505425L
                ),
                new EncryptedResponse(
                        "pDks/WpNZ3l71+1vgVQReVIjlSC5o7Jyepka/kbj5oUqtjyO3WopHyfAB7e1exqDl6dLDwsP0TcIndKmAPPdpQ==",
                        "Ob1ku/gu4dFdov1GVZIRZ8dSGeh2Kt8JbFACi/k5onc=",
                        "9/QPax/kk/VO5mto3ufdBA==",
                        1723109505425L
                ),
        };
        // ----------------------------
        // Start of test

        for (int i = 0; i < encryptedRequest.length; i++) {
            // Prepare values for this batch
            final EncryptedRequest request = encryptedRequest[i];
            final EncryptedResponse response = encryptedResponse[i];
            final EncryptorId eid = encryptorIds[i];
            final EncryptorScope scope = eid.scope();
            final byte[] sharedInfo1 = eid.getEciesSharedInfo1("3.3");
            final byte[] appSecret = applicationSecret.getBytes(StandardCharsets.UTF_8);
            final byte[] envelopeKey = envelopeKeys[i];

            // Construct Server's encryptor
            final ServerEncryptor serverEncryptor;
            if (scope == EncryptorScope.APPLICATION_SCOPE) {
                serverEncryptor = encryptorFactory.getServerEncryptor(eid,
                        new EncryptorParameters("3.3", applicationKey, null, tempKeyIdApplication),
                        new ServerEncryptorSecrets(masterServerPrivateKey, applicationSecret)
                );
            } else {
                serverEncryptor = encryptorFactory.getServerEncryptor(eid,
                        new EncryptorParameters("3.3", applicationKey, activationId, tempKeyIdActivation),
                        new ServerEncryptorSecrets(serverPrivateKey, applicationSecret, transportKey)
                );
            }
            // Decrypt request and compare to the expected value.
            final byte[] decryptedRequestData = serverEncryptor.decryptRequest(request);
            assertArrayEquals(plainRequestData[i], decryptedRequestData);
        }
    }

    /**
     * Construct EncryptorParameters for given encryptor and protocol version.
     * @param encryptorId Encryptor identifier.
     * @param protocolVersion Protocol version.
     * @return Instance of EncryptorParameters.
     */
    private EncryptorParameters getParametersForEncryptor(EncryptorId encryptorId, String protocolVersion) {
        if (encryptorId.scope() == EncryptorScope.ACTIVATION_SCOPE) {
            final String tempKeyId = "3.3".equals(protocolVersion) ? configuration.tempKeyActivation : null;
            return new EncryptorParameters(protocolVersion, configuration.applicationKey, configuration.activationId, tempKeyId);
        } else {
            final String tempKeyId = "3.3".equals(protocolVersion) ? configuration.tempKeyApplication : null;
            return new EncryptorParameters(protocolVersion, configuration.applicationKey, null, tempKeyId);
        }
    }

    /**
     * Construct encryptor secrets for given client encryptor and protocol version.
     * @param encryptorId Encryptor identifier.
     * @param protocolVersion Protocol version.
     * @return Instance of EncryptorSecrets suitable for client encryptor.
     * @throws Exception In case of failure.
     */
    private EncryptorSecrets getClientSecrets(EncryptorId encryptorId, String protocolVersion) throws Exception {
        final boolean appScope = encryptorId.scope() == EncryptorScope.APPLICATION_SCOPE;
        if ("3.0".equals(protocolVersion) || "3.1".equals(protocolVersion) || "3.2".equals(protocolVersion) || "3.3".equals(protocolVersion)) {
            return new ClientEncryptorSecrets(
                    appScope ? configuration.keyMasterServer.getPublic() : configuration.keyServer.getPublic(),
                    configuration.applicationSecret,
                    appScope ? null : configuration.keyTransport
            );
        }
        throw new Exception("Unsupported version " + protocolVersion);
    }

    /**
     * Construct encryptor secrets for given server encryptor and protocol version.
     * @param encryptorId Encryptor identifier.
     * @param protocolVersion Protocol version.
     * @return Instance of EncryptorSecrets suitable for server encryptor.
     * @throws Exception In case of failure.
     */
    private EncryptorSecrets getServerSecrets(EncryptorId encryptorId, String protocolVersion) throws Exception {
        final boolean appScope = encryptorId.scope() == EncryptorScope.APPLICATION_SCOPE;
        if ("3.0".equals(protocolVersion) || "3.1".equals(protocolVersion) || "3.2".equals(protocolVersion) || "3.3".equals(protocolVersion)) {
            return new ServerEncryptorSecrets(
                    appScope ? configuration.keyMasterServer.getPrivate() : configuration.keyServer.getPrivate(),
                    configuration.applicationSecret,
                    appScope ? null : configuration.keyTransport
            );
        }
        throw new Exception("Unsupported version " + protocolVersion);
    }

    /**
     * Generate random data with random length.
     * @return Random data.
     * @throws Exception In case that crypto provider is not properly configured.
     */
    private byte[] generateRandomData() throws Exception {
        byte[] randomSizeBytes = keyGenerator.generateRandomBytes(1);
        int randomSize = 3 + 128 + randomSizeBytes[0];
        return keyGenerator.generateRandomBytes(randomSize);
    }
}