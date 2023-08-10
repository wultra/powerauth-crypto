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

    private EncryptedResponse copyResponse(EncryptedResponse response) {
        return new EncryptedResponse(response.getEncryptedData(), response.getMac(), response.getNonce(), response.getTimestamp());
    }

    private EncryptedRequest copyRequest(EncryptedRequest request) {
        return new EncryptedRequest(request.getEphemeralPublicKey(), request.getEncryptedData(), request.getMac(), request.getNonce(), request.getTimestamp());
    }

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

    @Test
    public void testVectors_3_2() throws Exception {
        // Paste vectors here (generated by iOS unit tests)
        // ----------------------------
        // Shared constants
        final PrivateKey masterServerPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode("QvfZMNMXw7fMn1XCdMtgznw13flO++GiemMfi/nh7nI=")));
        final PublicKey masterServerPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("A4lTJ9UdVYu65PtTTqqJoCNY6yBB6g6oYRzzZlwXaTUK"));
        final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(ByteUtils.concat(new byte[1], Base64.getDecoder().decode("pf622NCVyYy52Lh9r+zt1th89Rw4W6vSCS2hBRidIUE=")));
        final PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("A5ZWZpY3C07h/XR42jPoAEi/K3iHvgBDuA2Mkm2NLRov"));
        final String activationId = "53F0F5A8-4D18-488C-94C6-5BDA3642B5BA";
        final String applicationKey = "Dj6YQz1rnkfePdb0Vjiq4A==";
        final String applicationSecret = "OOV55et3yLDjEu/rTCsFhA==";
        final byte[] transportKey = Base64.getDecoder().decode("aBo9FxL6Mm1dfqXXNh4Dow==");
        // Original request data
        final byte[][] plainRequestData = {
                Base64.getDecoder().decode("cyQcF5vShP3SJeHF/aXPQIESgdyGuLla0N2rdu2fw4DKnG22pVsYr1wZWapA2PrBEJtuS085wQmRMiJDJCUz18XQh5Rk3uyQEBJX+zKWUGFvD357QLw682X6vW7y"),
                Base64.getDecoder().decode("r/TEcBJxkXcaMT9jndECLFhthkZjHHrk41RQ2RnXbtZ+DICHVo8xJvsMQfeidmCdx4ao0C0KRCKRQyLTI6Wu/piL2RyGZXfesVKtUvTbB8953uGHyUt0Y/cvPqxSBaVOpZauZlAoIYcA3erlQWAD"),
                Base64.getDecoder().decode("aXhKAQSvPAwZSwttFtw="),
                Base64.getDecoder().decode("EKvkdrhh/EZ8HTQxMGMG9Of9RkRW"),
                Base64.getDecoder().decode("B4He8ZYEjjTKZSBjEKht8qvKbGePT5oNR9rUog=="),
                Base64.getDecoder().decode("vB+Vs9cAJnQs6EVaxjXHbBB3F+o3/3GxbzgGt1Pd6gRkZ6a06FcH0iJR4XDfI7qqQKSRDk2wUF9HLUHLtTugC8AhBAXLxZ+7mDdRfN7rTtwEM3M3jgpf4IwBLsWxYo8r+vtarVtsLmMU8Q=="),
                Base64.getDecoder().decode("UI4YFOWiNYmt9Wjkkflymi14PXMemLVzfLxPb03SNDFUmogXGGSFJ6t+vvaeDABeeA=="),
                Base64.getDecoder().decode("9MUnjcmVW7pWSUELs8hn8z7NIlaYivzlh0wqzd3VpR1c8ch3j4dyv4wQWTrb6YQL29YIj2bTkoqcprqOtG3H1U+FZeYwMTWb9Q0aonejp2eiiYTMrB3CAxtHXGr7NzQIlKCjn+lydXe8qd8MBnpOj0r9Faj4EvxN34pg/BLB"),
                Base64.getDecoder().decode("RFN+pA=="),
                Base64.getDecoder().decode("Eyk+zP7jzSQnNJtkx/496N28IAxJQOkq0Tfr87CdEky6pQ4CULN50I0SwBqiD960s6KYluK+BiYzZdu4N0uIUHUW8Ut14zrw"),
                Base64.getDecoder().decode("fiurxPQD/z/ttVO4Ez3p"),
                Base64.getDecoder().decode("fVmt7DLEZP+QHi+OsmHlHCK/ILhebG3tVAbUPkw6Az6wiGrWrzqiVrlbSMPKMJhYArr02HeQIKiY6VuhE7g="),
                Base64.getDecoder().decode("O0VAIhu1Wy7mFJv09xPFhVlMyxpLBF1Nycmwa2RvHV/5NjEmCGvRDpq3sDPJu5qqi8wVnUMKGFJRbP9cRqotxJjJ02cPY8FN2tu9tNsVxtsrjVdfjrpiY94mJXD0JKjO3J+M380prTL0qYsuPuw+r6it0gDZ412xOUTF"),
                Base64.getDecoder().decode("nI0GmlfTYSU76GxUYMDFLYL7NruA3NYRLArgFo5vTKKNwxpA6Wyt1jVLWzAGDxRJSpf94gtvV8nRNkaZD5Hawmsy1f16zEsDwpXXfs63fsFjBh6l69jsIQ=="),
                Base64.getDecoder().decode("sFmD4nrLgc96XVUGAM9LY6h7gvLR/qLEIJ4euZc6/4IkoV9kqxW/K64zK4YxTmWC1siSvc4N6DlcBrEO9ZYF/0l8yk32"),
                Base64.getDecoder().decode("L32KCTHlS8lfzZETnb0QG9lu/jqz4mmIumaZdZJSsGbhkA=="),
        };
        // Original response data
        final byte[][] plainResponseData = {
                Base64.getDecoder().decode("rz7tKte/OR7SnBic1RwqtfnVG4m1nHtHeOakSHQkSV1fAVyhPlYw2g=="),
                Base64.getDecoder().decode("dDcoC98K2TvLNxCsMJRQoTvQxziA81JhZpla+xS55HANRxoYWVBgTFQEUQdraN/7jLuVbVX/TNJDP4DyJr9usieWiGdCyCIF5Kb+Bd7X+AMNKsOm5Pm7jl7y8FoNv3JLEOETVFU7QVFdpLXNLGBxWZK2bW47t0sr7g=="),
                Base64.getDecoder().decode("apeTnnRsImCLYQT0MWVL+K18xBH33FwWNj7ys21OlV9vPWc2peQkjJkkRaHPKs+UOsvzZ7Qxsfpb5JmmWrGqZi/R62AS9iOtySNIy62yJbBUdBXk7g=="),
                Base64.getDecoder().decode("mzMYqz8fvZyJ5ZE="),
                Base64.getDecoder().decode("zCBNqRDraPScce7z4P92KnBk7j8K3hAlNyI2Dj9LwgXffUKMgR4bp5g7oK1z93mMeYbjaUdnHDQU4Rv9+Ri5WeSXSTC6IS0Ze3y3cXNWHediwSnJvcjbg2GKR1MriRoe9Gbg8gxyE6QTAShUVNKioo0="),
                Base64.getDecoder().decode("iPIND6+BwPQMcqr5rf4+bEOfiAwMOAZtBA=="),
                Base64.getDecoder().decode("OJJRvaQh5kD5vQcxnlymGhN+iW4PlPUWkZ6ru7R+sloyWMR46Vo5civlmJTE9GzhrzEKz12Pk1GZOqI="),
                Base64.getDecoder().decode("OHpOHkOlUqxjnjOKEkZarmx8qoa61JThNxG1VcNNqGeSSn0dQPPTjx5XEA=="),
                Base64.getDecoder().decode("QHJRy+bLzYQ56DnQiv/puTemsUmPyIwagiknl4AF7gnETDN0Hnx/bnFHqV9QmFBXsM7fiKQ5JZerVSXqnkaRcICBrxBAvjK/I77EEOXWxhmbXwqBvB74NSxyX46Q2rLchcam"),
                Base64.getDecoder().decode("yt72WmO5WdM="),
                Base64.getDecoder().decode("ad9cAdbazAnPt51lTdWMbxRIbYiTft/vpbnybIje/LeMJLfxV8CoZmplY3iqZeuHoYSIU6Y05L/bbts/9H7tjwSuzfuvueg09RJsKpvQ7Q2t8x/LwPuCySHXtyrNMqDtGEfB+i8tQYj8c6YUgzZMVQ=="),
                Base64.getDecoder().decode("WpwQXyL4Sxq3W3iltcIPJfFMB2ZM7vm/Bp3gFqezUae4Ma9PaNTD3Z00KqBzNhH6mSQuLoqLK0KyV0t7JuGJ0Gbz5VeKXT9DMVjN5aqaOXysaX45qUCjuXqgZl17qzk95R5LffpSvxq7c0Hw4q1chPkV44sUYvkPoRlA6nvOTat4JA=="),
                Base64.getDecoder().decode("M518ncWoKkTfHVEgvutVcXED3x8oEyQmMYxTN1J0gCyz1tvGEs+mabbbb31R4PnWFGpGHtu9vPe4ByKFWqj/KDElceSsvzwS"),
                Base64.getDecoder().decode("eKVL9AvB0Z5IFc9UPyW1x3c0cn0="),
                Base64.getDecoder().decode("scpkYabifHvdpeWHGhB1uKpCoSZetNV1uLOlpDUlxYUVezCYPXcTFxnOg2bis2Ybq/OZzfqFtE0WyKU3SgLDeoILaICcnEUxrFt5pAWrnINX9JoRTzuKxdhH1i7OcWIZBORGx7rP6ZTvUo2AvN23gSk6uQ/NrYIk2Y7PgQ=="),
                Base64.getDecoder().decode("ILj8xKFUivFN8XdzGc2ozs8nOhZFC5UET2k2hN2m9tTMXeNxO+3oiqHP5Bj9rA+KuqbGrubdzKy96EaCNbmOv7m3XLmVIIRjevbxsc0mUpKBVQ=="),
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
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0="),
                Base64.getDecoder().decode("AAAAAzMuMgAAABhEajZZUXoxcm5rZmVQZGIwVmppcTRBPT0AAAAkNTNGMEY1QTgtNEQxOC00ODhDLTk0QzYtNUJEQTM2NDJCNUJB"),
        };
        // Envelope keys
        final byte[][] envelopeKeys = {
                Base64.getDecoder().decode("8xvY05NTCrh1ORZYpzXRwlhSCnmexG2/Vrl+TIyyqRlCK3C/VinAOekMI2KJ+Tl5"),
                Base64.getDecoder().decode("cMaC48GSYVF0ypCLmFonLZZC5SqOC5gQizZL+weShg7hPExsrrAyQ7OffWICn1bQ"),
                Base64.getDecoder().decode("ZnPcNL4QeXsskARqyeBDrhLgdcCpgl1BOqVGLUv++sew3QKJcrPeeoI9JJW2C7Sz"),
                Base64.getDecoder().decode("flVpXycIoz5evvHwl0WPwouis3xUDgmkpVIX5cMPtCjtE/468TtWnsyT6GElJqvh"),
                Base64.getDecoder().decode("IGhzjhEwbUqA841eqirN4ELlyU7bkAL1TY0hQvNtSKYRJuoJgxzW0bxX6AxOxmek"),
                Base64.getDecoder().decode("ckI+bo4vmfpMv0mJ8PO0Jteyq5DDPhJb2EoTaE5omKq1QVIsZyTZA4RWqWYPygXo"),
                Base64.getDecoder().decode("z8G/4PU8/f0F+w71M6hVpBxD4rSULeJPDrL00WrPI+IlzJJKoL0fkTkaofjMdXrR"),
                Base64.getDecoder().decode("idkYQ1X2bgpiiUW1GfFRF5qoDndkbExI8ChnGnpXog1AQQG+EDznVCispRH7Dg5I"),
                Base64.getDecoder().decode("UR5o1BzyeG1/MzDUo/3aL4cr+baDq+/g38ajzJBR9EFU8U12LITVVkD6QG+J7/ZY"),
                Base64.getDecoder().decode("oGFxFAm92Dl+LxTc89A9jrIWaLhYzRAt0grLMtc8PN17bb91njUN/BrU4QEv7tLW"),
                Base64.getDecoder().decode("83dIrDflscTF81dSunypnYJYXsXRazi/vmR7KMulpzzWsqoGb9krEtMPF6A2jPpx"),
                Base64.getDecoder().decode("EEMXHHCthXrFODuvTnsk1mfv5x2Ap4uWpb5SfLY9n3HhnWACuhyynA37vQVjERfh"),
                Base64.getDecoder().decode("+1PdCRw0F0nrAJmDPo8Vk0/ynKOYg7yvU3J8NF2oqOczb3QHBkdnp1d7yRXbq4R2"),
                Base64.getDecoder().decode("8GTWGTe5hHYzUYsFD+MyJCH02+bsypzzAsAu+DivCcVgXELwwocwRlKW52hPWlrd"),
                Base64.getDecoder().decode("i0S0VYCOhb8Hy8bJxQzDicdz+Xb8kf5iB21fRkJcH4SwVgfUt4ZeAa2Zr4xHT2LT"),
                Base64.getDecoder().decode("7Hwtd6tg1MbYZkLiwlX0+hTS36KTNumlMhpUX0cL4Hv/W0vUyODXmh8sK/RAA+LP"),
        };
        // Requests
        final EncryptedRequest[] encryptedRequest = {
                new EncryptedRequest(
                        "A52X2J6Kv3Pk9pzBrS9DkGWe+VWtja97Qc2x4tScxijp",
                        "Y/RI/12XtWFjJoZ35ZP5qjzEtTQlP1MwLfouxl7IGCcD2ViJQrgZNXzprWl6vr0AwPwVjKid/eMTtWQ/UzR1iUX/3+bZcSMa4mf6BL6IZG5BHD3cyy/CuWMujVb7b/pk",
                        "dXDRJG5Os6aa7OH+UzPo/Zc64vgt6lG3HJpG+DD2JzU=",
                        "0SFu9RFJX6ICWwLBbyCuog==",
                        1691574778925L
                ),
                new EncryptedRequest(
                        "A2GLnDqMxzAW+UOSXcuzfYAFWCtpB54y5SYox68gSJyz",
                        "0f+GK6nQ4Xb6UAHEaGOduYYRlYksUKMGL4m+va7E/NKel/HWIx275Cs9q6wEGr4+mL+HI3LpoawMvUtyzVMCKVZMdfydeI52RhjEJ/VGZyV8WfYDesCWXNwO8hpQA4gg1mJ7dpgzUHtkNL5WE1xW8A==",
                        "xIpb0QvR8/eYY6mzr83uxAzobfAhOmzWqX5vEje/xik=",
                        "1QeyYfqs33xLAcqIDD4W2A==",
                        1691574778928L
                ),
                new EncryptedRequest(
                        "A9b3UjWvSNSTL775Lp7ezx/rwrhm/NDlqc9BnlZFo1qV",
                        "QEkEJtsz10cRISI8Ffoo4Q==",
                        "HaQzuCzZmyiT1L73IiBra1tIfH5FLFecZQWDcr7y0Mc=",
                        "bktVI9JYhBImjieHLFOHMg==",
                        1691574778928L
                ),
                new EncryptedRequest(
                        "AjYbGqORlDV+gxDE30KX/Pw/rp5QSFoszg95IGjG97eD",
                        "NFbdGUT02lrvnWPiUg4Bf1JC7h2a72gjiS/3Deemwto=",
                        "9rCNuyasTaD+zlMooTqjCf1OxbJv+Ux6n+Ae4/AS3UQ=",
                        "biCwFB3KLDYYTIz+JQpXuw==",
                        1691574778929L
                ),
                new EncryptedRequest(
                        "ArX+JBAJeMlANOG49AJw2G2gqtZy0RytmyUL39wGfIAE",
                        "aIj3mK5DZhfhFwOEfVks4tfxulzjvB+JcsjTjGiwA+o=",
                        "I+mc5RmUyZ0hxytQsBtgxde42eFaW1J2PXOPEHbO3FE=",
                        "c5alrPEZTX3XLPvDxut5Nw==",
                        1691574778929L
                ),
                new EncryptedRequest(
                        "A95OYXWnPizLEV7uWjaT23+yreMdBDJbibFVCZr1k0KP",
                        "+03DIVwC2VzT831OR6eT9v2kJMWOKVZJInNLvxL5JHDUYK9vlZs+qerzbEKd7iuz3l4rUuTezsNFc8HWufTIT+pKEUL+Y85blMUAXOexGZdmqQu5Y1B3bEChczS+65xS5uDUgjzcOyun0P57D/66bQ==",
                        "/bySs057ZpXOvmMqh8cBDvQDQT6JLMUFjEDrmJQQJG0=",
                        "7tCXyW/uBIBxi0/0+NoiyA==",
                        1691574778930L
                ),
                new EncryptedRequest(
                        "A2WWthoaQnftBuHl2ZnKaFe46We5HKEfx9RwLZ3ZVP3q",
                        "6Z4x+Fk72VPDTqmrxcBpO/TcXJX6kZ0Ln5ubO7tBiUp57bcHx/WeMtUnoBsKDBx6QcSAZjX/6d8K77M0JShOCg==",
                        "auvxv1fBsyFqtoO/CJu5AOPDmo+MB+C4/NLhLRJdKho=",
                        "cCycDgHZux43QgSJfNDiTg==",
                        1691574778930L
                ),
                new EncryptedRequest(
                        "A7RhUYEFnS6yDJEndCYY5g0V+r7y1FCYxXGSIlic+Uzd",
                        "IaUt8TDEGt0BEWxtA2CLCZQLebiTjr+W63wJtVsHwpXEdwkcFP4TTr951UeTVjiw1JDQ8rdJItuGVxW++5snN0JTOwpCDXHG4qmiqYX5shq7+vNHIweyqp9I66xiIvGnmmH7gvMfxYt1lpErgFhBh0C4XNyg//aP8VV9R+ZAntw=",
                        "pVcTn38myfn0cgGvDN1ivEO84UYcr9Xvw2jJwP+qwT4=",
                        "GDHyk7hjQpf1feiRl5XOCw==",
                        1691574778931L
                ),
                new EncryptedRequest(
                        "AoBgDBMQNtw0grBpQCaTG+sAmmmDqBe2Jt+yDgMwpXey",
                        "Jdlf72vSuP3CH8zQupRKvA==",
                        "LeELxWbPJ/5msrOeHGnpHJhyd1mY2O1zKGmSvfupaIk=",
                        "9V1kNg3WEex0qE/Q0utTmQ==",
                        1691574778931L
                ),
                new EncryptedRequest(
                        "Aj5xLTlr+egY6VNhvq0rpfT/4zoOrJwcoQSX3LhXfzkU",
                        "ZgheDGWUoclrAUZ0JBjQgQNfU8zJytqjoe57FlQCRkuWqd2k5VBqfS2DNO6XCEB34RC+v8YtngiG1bVVbeelA4ryqwa1boYeh+0nbl6tmQI=",
                        "pvbfPoA3rkv+v5To1MUwAe2qDhXpLiJc7Z7yMM6arUM=",
                        "Zwd4FUelZFzBNWggYfELuA==",
                        1691574778931L
                ),
                new EncryptedRequest(
                        "AwLGa0FGNQzCeDf4LthYbrNAgttu3hNoSK7PjDihIhHt",
                        "zjKfsXQFcPmPDMCXOYRyeA==",
                        "5k9LGagvnqY1y+D+8z/RcAZ3Gzjqg3iBNp1fG/gmgzk=",
                        "zWKFrLfYB7Qqg7f6rrFzmA==",
                        1691574778932L
                ),
                new EncryptedRequest(
                        "A0MHujZdkKZL2KQhV9ytKaiXfS+xdwuKA2/db36Mzih9",
                        "2aNZZ+XRbWD2SnZls2Li2b2tA3Ic24OreKbgoulseVpR2qiXme3XXPRgwFB8gjr9LIWl52PrT8/EKBWNhNWMDg==",
                        "jzgE6ca4dCVvPuI7wCBz+WEjs35GJsUZAIk83bgfhhg=",
                        "dRuD2KYe7Z8kGHhSEalcwg==",
                        1691574778932L
                ),
                new EncryptedRequest(
                        "AiZZeoxxOF8l+q2HG8AE4zWgXpZRgfq1wVH8T2V86xmF",
                        "E7AmPfL3WGqvsOEO5aEHJhEQ9AM8x+bRLr8Puiy+AGJ34ZxDO3MzQmYgwrUcYfXWc+qA4HLNcnUvDBZaXaQT6t/CRuNAnDd+SBV/J3IIjuzy0SuMXVsQDly/Cko3z+7zBVDYlEnQX5I9ym2o9tEAoyEWbAKgjWV474crhMv3eFg=",
                        "iPcgz741be5PAKTQeZCIp5MKcTSLmG/U/cjt2NbrJ6g=",
                        "p5afCJicnaqf0I0HNJV8Ww==",
                        1691574778933L
                ),
                new EncryptedRequest(
                        "A/JsBsMLs0vkT/tSxAL+Agcdwq8d1y/98TUNpCXkT2dJ",
                        "XMt7iqMzqhrqrX6dNWXA4f3kRHdgQ3am4mTNk00m4eDlaP4F5s8JqKvR5uMg/PlL+ylsghmTlfQadAhVtP2w++G05T5kOu0iWTJvLsBBJTkdhclsR0LefDbT1R+sCqr9",
                        "NhaUiZ7c2NGoaTo8xVEnxFEMH5vXcCoNhV0sF5fpCEY=",
                        "1IWnOBlh/XTaFcon4p0czg==",
                        1691574778933L
                ),
                new EncryptedRequest(
                        "A9SSBIC608OIu9LM8hHnu6rJYmULNIR2kLUApa98KScz",
                        "wTAEd308FuM21U2oGgAXmdTIF9jfBHs47xOzapV/rkbukQ9HBF6z8bge1H4tyZpfDk2dzavKyEASEpX9fG/Tm5I4RgRlGz6G0NhnGR35zLU=",
                        "AzlIVR276sEBqLiQ4n/fCKT19tJGtRXgBLiGAFT6LXA=",
                        "/o+C2efRQqROVETqxgbBpA==",
                        1691574778934L
                ),
                new EncryptedRequest(
                        "AhEQi7+LSZWXMagQ4/GmDWWHdWpI5du90QqwdpzHyv+n",
                        "4KNCYb/QXbWRZswlognRQRRBxuq7vkTHx0tLoYKdYL6/eC1UOAUZF0mClFSlNzLa",
                        "ZbibsisLIoU5Dy8xeoXGzO7hdc5tl7ba5X9x8A5vqYY=",
                        "l9kwiYvqCZREpVV5Nkdb4Q==",
                        1691574778934L
                ),
        };
        // Responses
        final EncryptedResponse[] encryptedResponse = {
                new EncryptedResponse(
                        "EAxa4WSgWUORLDswy5ZkcwRrFXDJLd0XWRx7+fim9GeaWOWllF4Mkpa0OBpI2qSz",
                        "MO/CXXwWogrZkjVQeI/K7jIV6ub/zpDJD8AO9mZndR8=",
                        "G1Lrun2cWQh0Uj1a5ENesQ==",
                        1691574778928L
                ),
                new EncryptedResponse(
                        "l5PdR47+MuIAbQ2mDM3B12rcAFJ+VTO/QomF4niJfSGWNQKqNs6+ekrUlhiSXlBuV1kxpx1vs2DgiFRGs5AE6I4i3R15jf2O20kKNbxnrOhXwI7On/f7wfZasBE7LT325DY3hoqOmE1Q8pY+ohifo4MPaidb+t24Hvtm//jmusU=",
                        "GQlmxzBSuV4HOeUQWfA0BsmeWW5zFfqLvOkA58uELmw=",
                        "gKAdWHMAYbLtLlR6w7pAWQ==",
                        1691574778928L
                ),
                new EncryptedResponse(
                        "fgG5H1/IHH6v8Is42w4Fn4JinfAp85D9aiKNjgUrc1ypDjF5Rpgfc+ftctuFOQlfbk66v06Bu8W8IpOw2lhgvgcpNAi7n/0lmEbOafkB9lojpuby0mb+EWqk6KJoJ56E",
                        "Fu4TR07FwTyVpyHW66sVWKF7qKjhmyOVR97/kJhNGHU=",
                        "fCjFm4d14H2M88V5Ol9OfQ==",
                        1691574778929L
                ),
                new EncryptedResponse(
                        "vKXsAOpZEUz3uT5RR3LvEw==",
                        "MBth5/VbFQVByqxCBxv7mekl9IXzjH4AQCtOOjbovYU=",
                        "EtTy94Uj2VVVFY60nIiFGw==",
                        1691574778929L
                ),
                new EncryptedResponse(
                        "jvn2fDTBPi0SJxeqxlxsGERmOro8wMQ/QKOtAh+HUr9cUSueBbk86ZUmNiMbTvMhGI/oINsF8/n1nnB5Bs9GApuwuyeykdVlVQzo0Rf1idvynLdtSaqCtOclct1XbYN3fP72o33CwYv6NtOitXqPzbFlUn6PsINmyJs2XBt1WRU=",
                        "Kpjb66tfwy4vhyLPvgK80slhOoSBqgth4mhrz/SK+Ao=",
                        "8D5XlZnMe62GJ4C59jaWXQ==",
                        1691574778929L
                ),
                new EncryptedResponse(
                        "09VybDzopGDtQAA0QCpMg33ErhfmZnO+ZwZWXKnVwvs=",
                        "Q6LGtECtCYsYN+/kLfCZuMzjqWQs0wwVT975Q3cojos=",
                        "Lp2vXKX1bkNeQpkayUejmQ==",
                        1691574778930L
                ),
                new EncryptedResponse(
                        "6PsBq25o5F9Q7082Z5tXD5gJ6X7qq0mC8RCCulKw7QErhNe0Wn9dimI8C5K7sLWYnH0qy92akqK2cETBV+gysQ==",
                        "rBxF26Db8l0vq6uy9s4Deggpb8pi6nGbfYEjQehhxew=",
                        "bcqRO/ZXopXPQR/WRr0wew==",
                        1691574778931L
                ),
                new EncryptedResponse(
                        "70/KO2C/SsQnnM3AkPbPkbQhGv4bacDWe2XiSEmF9caV+6Z0tm22FZkIfTF0zhWL",
                        "hzNvZkg0WU8EzFkf41eqq/EJPi55NOAz4qxaEv5IQwk=",
                        "6qQOJWzgKkAxOb6FXJzBHw==",
                        1691574778931L
                ),
                new EncryptedResponse(
                        "o80CSvhjPJWtgDgIHrWt9obWpRH1AMAHOFX6gj9avzfZT8l/gWcQS2RebKTcFdB43Z8/2Tkm4mScQr/9TAMO4mQrNCd+h5YD+hna+h38hrsuxljdO3hbsRSq9oaarVEIgcTgJD9kVGp3V9jgJjTC5g==",
                        "56ptXMP1WtTSl2Cs5S7ViWC0QJS6i2QhCu4Li7LPLWQ=",
                        "sO5k1Ya2e4dcabLuiSHWIw==",
                        1691574778931L
                ),
                new EncryptedResponse(
                        "zMNVK6uUANOHTDL8NC324A==",
                        "+cn6/8Lk3ky5lu1dLWp/aTKCH07wRzIOe45VitM11GQ=",
                        "GU620oPimuCJCSgurKW0wg==",
                        1691574778932L
                ),
                new EncryptedResponse(
                        "mR68ArSeFUM5Fh/ep+OWiLea7t3q92RyQ3KyucuRegPQoIbgWyYWOla3k6+to52QqBjJpzO9vr/WPQoKXjlp9oz+LAhQIj7jYkO4zwAASqiUwvi7GH0vu5pfuBjvNkeU6o8lkZl3Aors/i1tA1IhQlNrKRnWkETyc+STXG8dWys=",
                        "OmfFQT69fVkMKmtEHZYMgCwW2c55L9yxuZQHmmk26Xs=",
                        "X+jCfObVK9JkTPakmnrPpw==",
                        1691574778932L
                ),
                new EncryptedResponse(
                        "uAGhZWWTMicZAmwUIwUfOxzstRj0uZHIe3v5va0tJyPFoaNqJ6q5qPT6qiCL+cUCp6S6aENNv6jAVoXXQWnwpunMxyjrXiBEhGAWBEbOle1eRqbmrSZRD6HDnsIGsdxEsx213KMtZbrs5WY35epN9p0YQhjqd9w8lDOzc4SGsp1K/xEVN2uDZdrG0iCdboHl",
                        "VST8O9NWrEOraL019z/4LjkNMjy2+c92zrZiuuRa8f0=",
                        "o8QXzIqTIC13WLOZw9KedQ==",
                        1691574778933L
                ),
                new EncryptedResponse(
                        "8R69xDq8+axSwhbUZcsfNLGfUs+BYp/rePRxJXK+1lvJZa1YRuzRo1CWZBihu/a62XSNy8PN178MeHeCY0IJu5lBv36Y6S1uanXUGsS/wv8=",
                        "zCBExefQymdcnFyb9AkmR3/eCek3Ab0ZLY5q5eUMnEk=",
                        "8mdA/tc9aGaeqhtHAYPRKA==",
                        1691574778933L
                ),
                new EncryptedResponse(
                        "EnoNRJibTNg/iSWaZgNONWFUogW3u8VRUyvVCUdZSy4=",
                        "KSSbwGzSDZKVqCgZVu8gCeKC+xquAatf49H8Zncv7HI=",
                        "kEDMIEQhVnNr5JPWzhgauA==",
                        1691574778933L
                ),
                new EncryptedResponse(
                        "xsJE4BuVDoaOEl59MfSBa9ZFVXWHLnGlqhji8KCswWZ12c+DeYl3obmZpOZaqH9jaO94IvWGOA4/+PNO0oth4ALfdz4EN5oaeAImYD7aGjklJZ79xKnzMoR5mSk0ga4Lyxs9AqYdOgbwdMWsFAfwXiqCr8wbpWt59AjFUf72U+U=",
                        "GVid+XHmkB36GBZ20S6Z/Y94lVVgbp5/i0lXCjfcvvo=",
                        "2HO7TGr8e6A4fliNmnUbJA==",
                        1691574778934L
                ),
                new EncryptedResponse(
                        "/uo7GDQPgvz8TbQv36PQOlAvCNSGdcBS/+OkhasZ0mpiD0lOfjSNQhZbL9bHrx/PbqLocgsBd9K6LbafLH6yjs28mCeHWfvZo/NF3SsCXTSi+oEtDINVJjmZ2QZsMbLW",
                        "6G465KAjrg+CxgBsMN1bP57dIkVAzufMScXLEEWmcvY=",
                        "j4TXSIuP6FlwwEkz+wYaFg==",
                        1691574778934L
                ),
        };
        // ----------------------------
        // Start of test

        for (int i = 0; i < encryptedRequest.length; i++) {
            // Prepare values for this batch
            final EncryptedRequest request = encryptedRequest[i];
            final EncryptedResponse response = encryptedResponse[i];
            final EncryptorId eid = encryptorIds[i];
            final EncryptorScope scope = eid.getScope();
            final byte[] sharedInfo1 = eid.getEciesSharedInfo1();
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


    private EncryptorParameters getParametersForEncryptor(EncryptorId encryptorId, String protocolVersion) {
        if (encryptorId.getScope() == EncryptorScope.ACTIVATION_SCOPE) {
            return new EncryptorParameters(protocolVersion, APPLICATION_KEY, ACTIVATION_ID);
        } else {
            return new EncryptorParameters(protocolVersion, APPLICATION_KEY, null);
        }
    }

    private EncryptorSecrets getClientSecrets(EncryptorId encryptorId, String protocolVersion) throws Exception {
        final boolean appScope = encryptorId.getScope() == EncryptorScope.APPLICATION_SCOPE;
        if ("3.0".equals(protocolVersion) || "3.1".equals(protocolVersion) || "3.2".equals(protocolVersion)) {
            return new ClientEncryptorSecrets(
                    appScope ? KEY_MASTER_SERVER.getPublic() : KEY_SERVER.getPublic(),
                    APPLICATION_SECRET,
                    appScope ? null : KEY_TRANSPORT
            );
        }
        throw new Exception("Unsupported version " + protocolVersion);
    }

    private EncryptorSecrets getServerSecrets(EncryptorId encryptorId, String protocolVersion) throws Exception {
        final boolean appScope = encryptorId.getScope() == EncryptorScope.APPLICATION_SCOPE;
        if ("3.0".equals(protocolVersion) || "3.1".equals(protocolVersion) || "3.2".equals(protocolVersion)) {
            return new ServerEncryptorSecrets(
                    appScope ? KEY_MASTER_SERVER.getPrivate() : KEY_SERVER.getPrivate(),
                    APPLICATION_SECRET,
                    appScope ? null : KEY_TRANSPORT
            );
        }
        throw new Exception("Unsupported version " + protocolVersion);
    }

    private byte[] generateRandomData() throws Exception {
        byte[] randomSizeBytes = keyGenerator.generateRandomBytes(1);
        int randomSize = 3 + 128 + randomSizeBytes[0];
        return keyGenerator.generateRandomBytes(randomSize);
    }
}