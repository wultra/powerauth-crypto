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

    private String APPLICATION_KEY;
    private String APPLICATION_SECRET;
    private byte[] KEY_TRANSPORT;
    private String ACTIVATION_ID;
    private KeyPair KEY_MASTER_SERVER;
    private KeyPair KEY_SERVER;

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
        APPLICATION_KEY = Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16));
        APPLICATION_SECRET = Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16));
        KEY_TRANSPORT = keyGenerator.generateRandomBytes(16);
        ACTIVATION_ID = UUID.randomUUID().toString();
        KEY_MASTER_SERVER = keyGenerator.generateKeyPair();
        KEY_SERVER = keyGenerator.generateKeyPair();
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

        if ("3.1".equals(version) || "3.2".equals(version)) {
            request = copyRequest(validRequest);
            request.setNonce(null);
            assertFalse(validator.validateEncryptedRequest(request));
        }
        if ("3.2".equals(version)) {
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
        if ("3.2".equals(version)) {
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
     */    private EncryptedRequest copyRequest(EncryptedRequest request) {
        return new EncryptedRequest(request.getEphemeralPublicKey(), request.getEncryptedData(), request.getMac(), request.getNonce(), request.getTimestamp());
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
                        "Avlav7hfDwCA1zJq6gyczWtUn+MhNCebikIH7rkUkoHB",
                        "jZ1y4ZkJpvRTDHFXQ+J9jsWaFuV0AvqpUXFDCi3bH90YCutTufSamKXpEIhFfqBmhzYak2g6LBUfgmTJ7c74D+eOqGRn1EwZOcgVHKbaFjgthwSUnD8E7maEK9u5qmVdi52drt9vQ1Cye5jWn0vSTKmvSkfcQcmK42o/0r/8LXs=",
                        "ovJWPbaRr/+9nDLwHhej1u9iNVg0OVVNNO2zI88AM9g=",
                        "BKIsGcbgqAqEKhuEJFX25Q==",
                        1691762307382L
                ),
                new EncryptedRequest(
                        "A97NlW0JPLJfpG0AUvaRHRGSHh+quZu+u0c+yxsK7Xji",
                        "qYLONkDWFpXefTKPbaKTA/PWdRYH5pk9uvGjUqSYbeK7Q0aOohK2MknTyviyNuSp",
                        "DNlZdsM1wgH8v2mAROjj3vmQu4DI4ZJnuTBzQMrHsew=",
                        "ZQxUjy/hSRyJ3xBtqyXBeQ==",
                        1691762307384L
                ),
                new EncryptedRequest(
                        "AtSsPjiwbh3GnWYjCOejGIGg0LEbl1X6SY4f1F77PG2I",
                        "px6h9Hu+wyH38YySO6istbinaF3ALyrBraad0qhTCJZrYrVlTv1bEnfvElBupQzGUx3SikSqaOjR+UKzj9TVfa2rw36LkSIVFZYk1gG6xW3U852ZvJpuTtw6h7WhFYks",
                        "bySXBDU/9mDx9T8i9DFWX7Xn4O6HZK2EMLpA+ogv3eM=",
                        "6p2OQ20Ezjd+RcCAr2w34w==",
                        1691762307384L
                ),
                new EncryptedRequest(
                        "AnjhcBNyzpyUs8TnvW164zfwVk6UQjof8zueumjUADlB",
                        "rQDj9EseF9GvJY6a0YCExA==",
                        "Mpu0lek/SXf7JvxnlEngv/Bx8nFhxi54vHVrBr0f7H8=",
                        "0qdMsQVKjhE8gwRm8It2Vg==",
                        1691762307385L
                ),
                new EncryptedRequest(
                        "Aqa/2aW4VuZTXaFoc0rcc67RotG0rbiqpvontLsdoLIe",
                        "ic3LxIfwgK9XbckAxivYvMdwuAL9nOC/Kdry4w/1xRw=",
                        "OyQcPCU8opsBN88vCE/9Km53a8sNqamIMIwxNfOOyto=",
                        "6YzESLD7x6ANSxeirDAXZQ==",
                        1691762307385L
                ),
                new EncryptedRequest(
                        "Aomhgt+8zAMsuRYgsVJMioFFPLP6eK+4omcLfftS/PHK",
                        "xNdtHsq28x+cFGxLGJbW6l7SscETdLRHejmXYETzU8670YyaqpiGOO5276vb3XDnxM6GjKHEztXruz8YBQzWKYqc6YVU4WqKMNHBu1A/9yKY8KGE+XsSxyrkZxoIM4oZuUp7p1ui+H87PPY8Vs/c9dMM5YUMYVUFZA1kBnzskKs=",
                        "z05w9DN9CKWtURAr0g7D5Kya8Jvp+CQFLNz2Fy1inaI=",
                        "fWn7lYWXckz72X4elEU+3g==",
                        1691762307385L
                ),
                new EncryptedRequest(
                        "AoCXG9cbmKBSPP2zi3pOuJQV6dENZ751dUhEGoDqLWVB",
                        "fqsJXWuIt2rwwsWLu8TbPnCxwha6PTGTpzmsLq/Tdynt5YcrEBk9wlRaQIXzWi0KbES20BjJbgL7JIaY2qj/XlFU+vxB+vybUnHrtpe2NaDthaYgdEecX3W1uzpyd745ogDSGe19gOqwXCFCRFLF+w==",
                        "T/tx0z+61zPosCa2Y0oJBepFOOfn0O1lrMKkr9RSVNY=",
                        "YQwJfuPmImzyBhGqZ7QMNw==",
                        1691762307386L
                ),
                new EncryptedRequest(
                        "A/5KJP3Cb8DhNjo8Cs2juYLwpswsUBJe6XXdwowIelP7",
                        "wUXXg0vgkZjqvqIfJm7YPgk+7bwgWSttizi+uSKAE4z8dOY8zUp0uvsvsUqDIvnhisnc82IyS/kGhSg1QWyzjAdfr5rWehl+aS+e8GPIu3Ok8n0qNG9TJ1n/UxuD6Ok/WTCHsRW2QoU2I8vB6BAMUw==",
                        "J88D9JrcVVmVlUNe5g6IzEHd3m+PqfSzBNyCfEb+UXg=",
                        "vr95iaeHXK4W0o0WU3MAkQ==",
                        1691762307386L
                ),
                new EncryptedRequest(
                        "A3TP+jPFrRgQd563V8goh2wJgvRS9eMpwjo9tOivLboN",
                        "8MjZ4+3cUC7IkwyNK09WSDMOrMpNwfHrXUM3A/19sjyOVZJIAl9HYJySlN8h9A2qrG7l0Eu6nFUwjDH8+NHfqBHCdOAnpncwgANE5GetzgA=",
                        "pmWeeMSroONdztB05rb6932llfAJJo6+uqLvwYq01dw=",
                        "ecQuWdjhJB90a0vxXJCHDA==",
                        1691762307386L
                ),
                new EncryptedRequest(
                        "A0w7WTl0Q3vhxlyKJWV1hM1YC484mysCqhjay9uFSmvG",
                        "K0Ep8dWNhD99yZm/mShFy53DYbTCntm582rlWwskPfcKTE7b/7gBFbXaGly1o9cmQ9Wv9RjBx8Ai4rda/KKbyMq3ZaX6ljAWFpOmqUIgMUQ=",
                        "Zr7vEn6WBYkFFZRAvq3UdRR/OWF2uOK0ABik9fytOUo=",
                        "20zLGrzcBPr6aPWQTOESuQ==",
                        1691762307387L
                ),
                new EncryptedRequest(
                        "A4o3ZVufjyXvJnc98rvHxTbQgCpY1dwMkJs4mKkT78up",
                        "8hYJGXgHLD8tH9sFrRlU6fxGWU/JdlSBpPkL178OFRdORMXTY/ReMRbajQD3bXKzXjmhdYR5X13fHsmiuvHIQVPRFB0ZyS43HT/uEDpWh8SWByKjNB5je6ftEySsmpKGp0KvmjXgiIRX7TiRzwJ03g==",
                        "VX9TB4hPM7/6U/NQvBNR6VaP1loyq2ZhcmEu4NWCU7g=",
                        "Z5XV6HOqZ3ftaxEkdgjIwQ==",
                        1691762307387L
                ),
                new EncryptedRequest(
                        "AhVR4QxfHA5resv8ppMANxzZwkaWphsmtA/EENi8Swjp",
                        "ASC8xiBSyjx8wGwf71U9Zk4nZT9w//8AafiZaT+9RtObUmb1HjguWv3Xpqejnf5kml3Z7sXDYgFemFYLklhL5A==",
                        "8wlb+Pz3UulREpbcBV4GfiY4bePugBPV6ywgaycvrpU=",
                        "Y6DDsiZb40xV1lhNNWloiw==",
                        1691762307387L
                ),
                new EncryptedRequest(
                        "A9ok7XXLWWWtQAxERdvFv3I31D+pgZuY3cVSbjpJHLda",
                        "+b0Ki6WcoaoGJhBrGR28zeMqS91XMmCCtO/HU3xaKNg=",
                        "jmkaGcZ+qnrMXtD1R7YhRmJJU+d3y6/nATjNno7DA0A=",
                        "MrgNNwmotGQZspWUFNMuRw==",
                        1691762307388L
                ),
                new EncryptedRequest(
                        "A24fQipKuaW7sOmXbpZDW+QetW/aBmS+2fkrkSdNDlQe",
                        "GaXg6TBM+H4ru/E25gvV0g==",
                        "xV19DEuOG+SGpT22GU55mVQqU4I7/+vgWNFKDq6tK5k=",
                        "mXHJkh/NUVzxLAXRH2r+9g==",
                        1691762307388L
                ),
                new EncryptedRequest(
                        "ArzfJWjDZrjndvQg3aFxZme6w/Z5P4uV4mBClCbURJuv",
                        "cbG2zh4dp5Ig65/Gdz97ZLm1vWeLfSUbIIoLWQXQm5pUVLkHJ55Mrl4TwdK6kTG0",
                        "lawZCFwh0NTpNafMwC92/ndMnkryG4yxfAvp/4q1F3Y=",
                        "C48N0ekaenicTtsb6LEf1g==",
                        1691762307388L
                ),
                new EncryptedRequest(
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
                        new EncryptorParameters("3.2", applicationKey, null),
                        new ServerEncryptorSecrets(masterServerPrivateKey, applicationSecret)
                );
            } else {
                serverEncryptor = encryptorFactory.getServerEncryptor(eid,
                        new EncryptorParameters("3.2", applicationKey, activationId),
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
            return new EncryptorParameters(protocolVersion, APPLICATION_KEY, ACTIVATION_ID);
        } else {
            return new EncryptorParameters(protocolVersion, APPLICATION_KEY, null);
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
        if ("3.0".equals(protocolVersion) || "3.1".equals(protocolVersion) || "3.2".equals(protocolVersion)) {
            return new ClientEncryptorSecrets(
                    appScope ? KEY_MASTER_SERVER.getPublic() : KEY_SERVER.getPublic(),
                    APPLICATION_SECRET,
                    appScope ? null : KEY_TRANSPORT
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
        if ("3.0".equals(protocolVersion) || "3.1".equals(protocolVersion) || "3.2".equals(protocolVersion)) {
            return new ServerEncryptorSecrets(
                    appScope ? KEY_MASTER_SERVER.getPrivate() : KEY_SERVER.getPrivate(),
                    APPLICATION_SECRET,
                    appScope ? null : KEY_TRANSPORT
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