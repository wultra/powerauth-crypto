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
package com.wultra.security.powerauth.crypto.lib.v4.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.wultra.security.powerauth.crypto.client.v4.activation.PowerAuthClientActivation;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationVersion;
import com.wultra.security.powerauth.crypto.lib.util.HybridPublicKeyFingerprint;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.model.TestSet;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.aead.Aead;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kdf;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyLabel;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Generate test vectors
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class GenerateVectorDataTest {

    private static File testVectorFolder;
    private static ObjectMapper objectMapper;

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC = new MlDsaKeyConvertor();
    private static final Random RANDOM = new SecureRandom();

    /**
     * Register crypto providers
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());

        // Create folder for test vectors
        testVectorFolder = new File("target/test-vectors");
        if (!testVectorFolder.exists()) {
            if (!testVectorFolder.mkdirs()) {
                fail("Could not create folder for test vectors.");
            }
        }

        System.out.println("Test vectors will be generated in folder: " + testVectorFolder.getAbsolutePath());

        // Create Object Mapper
        objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    /**
     * Characters used in {@link #getRandomString(int, int, String[])} method.
     */
    static final int[] RANDOM_STRING_CHARS = {
            32, 33, 35, 38, 39, 40, 41, 43, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
            65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
            97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122
    };

    /**
     * Generate random string or select random string from predefined set.
     * @param minLength Minimum string length.
     * @param maxLength Maximum string length.
     * @param predefinedSet Predefined set of strings.
     * @return Random string.
     */
    String getRandomString(int minLength, int maxLength, String[] predefinedSet) {
        final boolean fixedLength = minLength == maxLength;
        final int upperBound = fixedLength ? maxLength : maxLength - minLength;
        int length = RANDOM.nextInt(upperBound);
        if (predefinedSet != null && length < upperBound / 2) {
            return predefinedSet[RANDOM.nextInt(predefinedSet.length)];
        }
        if (!fixedLength) {
            length += minLength;
        }
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i <= length; i++) {
            sb.appendCodePoint(RANDOM_STRING_CHARS[RANDOM.nextInt(RANDOM_STRING_CHARS.length)]);
        }
        return sb.toString();
    }

    /**
     * Generate random bytes with random length. The length is within specified range.
     * @param minLength Minimum requested number of bytes.
     * @param maxLength Maximum requested number of bytes.
     * @return Random data.
     */
    byte[] getRandomBytes(int minLength, int maxLength) {
        final int size = minLength == maxLength ? minLength : minLength + RANDOM.nextInt(maxLength - minLength) + 1;
        final byte[] bytes = new byte[size];
        if (size > 0) {
            RANDOM.nextBytes(bytes);
        }
        return bytes;
    }

    /**
     * Generate test data for common KDF function based on KMAC-256, used in protocol V4.
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    void testKdfV4() throws Exception {
        final TestSet testSet = new TestSet("kdf-v4.json", "Test vectors for common KMAC-256 based KDF function used in protocol V4");
        final String[] labels = {
                KeyLabel.AUTH.value(),
                KeyLabel.AUTH_POSSESSION.value(),
                KeyLabel.AUTH_KNOWLEDGE.value(),
                KeyLabel.AUTH_BIOMETRY.value(),
                KeyLabel.SHARED_SECRET_EC_P384.value(),
                KeyLabel.SHARED_SECRET_EC_P384_ML_L3.value(),
                KeyLabel.SHARED_SECRET_EC_P384_ML_L5.value(),
                KeyLabel.SHARED_SECRET_ML_L3.value(),
                KeyLabel.SHARED_SECRET_ML_L5.value(),
                KeyLabel.AEAD_ENC.value(),
                KeyLabel.AEAD_MAC.value(),
                KeyLabel.VAULT.value(),
                KeyLabel.VAULT_KEK_DEVICE_PRIVATE.value(),
                KeyLabel.KDK_APP_VAULT_KNOWLEDGE.value(),
                KeyLabel.KDK_APP_VAULT_2FA.value(),
                KeyLabel.UTIL.value(),
                KeyLabel.UTIL_MAC_CTR_DATA.value(),
                KeyLabel.UTIL_MAC_STATUS.value(),
                KeyLabel.UTIL_MAC_GET_APP_TEMP_KEY.value(),
                KeyLabel.UTIL_MAC_GET_ACT_TEMP_KEY.value(),
                KeyLabel.UTIL_MAC_PERSONALIZED_DATA.value(),
                KeyLabel.UTIL_KEY_E2EE_SH2.value()
        };
        for (int i = 0; i < 100; i++) {
            final String label = getRandomString(4, 20, labels);
            final int key_size = 16 + (RANDOM.nextInt(4) * 16);
            final int out_size = 16 + (RANDOM.nextInt(4) * 16);
            final byte[] key = new byte[key_size];
            RANDOM.nextBytes(key);
            final byte[] custom = getRandomBytes(0, 96);
            // derive key
            final SecretKey derivedKey = Kdf.derive(new SecretKeySpec(key, "RAW"), label, custom, out_size);
            // store test vector
            final Map<String, String> input = new HashMap<>();
            input.put("key", Base64.getEncoder().encodeToString(key));
            input.put("label", label);
            input.put("custom", Base64.getEncoder().encodeToString(custom));
            input.put("outSize", String.valueOf(out_size));
            final Map<String, String> output = new HashMap<>();
            output.put("derivedKey", Base64.getEncoder().encodeToString(derivedKey.getEncoded()));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for KDF function for passwords, based on KMAC-256, used in protocol V4.
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    void testPasswordKdfV4() throws Exception {
        final String[] wellKnownPasswords = {
                "nbusr123", "123456", "password1", "iloveyou", "querty123", "abc123"
        };
        final TestSet testSet = new TestSet("pbkdf-v4.json", "Test vectors for password based KDF function used in protocol V4");
        for (int i = 0; i < 100; i++) {
            final String password = getRandomString(4, 16, wellKnownPasswords);
            final byte[] salt = getRandomBytes(32, 48);
            final int out_size = 16 + (RANDOM.nextInt(2) * 16);
            // derive key
            final SecretKey derivedKey = Kdf.derivePassword(password, salt, out_size);
            // store test vector
            final Map<String, String> input = new HashMap<>();
            input.put("password", password);
            input.put("salt", Base64.getEncoder().encodeToString(salt));
            input.put("outSize", String.valueOf(out_size));
            final Map<String, String> output = new HashMap<>();
            output.put("derivedKey", Base64.getEncoder().encodeToString(derivedKey.getEncoded()));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test vectors for low-level AEAD encryption used in protocol V4.
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    void testAeadV4() throws Exception {
        final TestSet testSet = new TestSet("aead-v4.json", "Test vectors for low level AEAD encryption routines used in protocol V4");
        for (int i = 0; i < 100; i++) {
            final byte[] key = getRandomBytes(32, 32);
            final byte[] keyContext = getRandomBytes(4, 32);
            final byte[] nonce = getRandomBytes(12, 12);
            final byte[] associatedData = getRandomBytes(8, 48);
            final byte[] plaintext = getRandomBytes(0, 256);
            // encrypt data
            final byte[] ciphertext = Aead.seal(new SecretKeySpec(key, "RAW"), keyContext, nonce, associatedData, plaintext);
            // store test vector
            final Map<String, String> input = new HashMap<>();
            input.put("key", Base64.getEncoder().encodeToString(key));
            input.put("keyContext", Base64.getEncoder().encodeToString(keyContext));
            input.put("nonce", Base64.getEncoder().encodeToString(nonce));
            input.put("associatedData", Base64.getEncoder().encodeToString(associatedData));
            input.put("plaintext", Base64.getEncoder().encodeToString(plaintext));
            final Map<String, String> output = new HashMap<>();
            output.put("pqcCiphertext", Base64.getEncoder().encodeToString(ciphertext));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for activation data signature (V4).
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testVerifyActivationDataV4() throws Exception {
        String activationCode;
        final PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
        final TestSet testSet = new TestSet("verify-activation-data-signature-v4.json", "For \"/pa/activation/prepare\", client needs to be able to verify the signature of the encrypted activation data (for version 3 of PowerAuth protocol: activation code) using the server master public key, for example when it's stored in the QR code.");
        final IdentifierGenerator identifierGenerator = new IdentifierGenerator();

        final int max = 20;
        for (int i = 0; i < max; i++) {
            activationCode = identifierGenerator.generateActivationCode();

            final KeyPair kpEcdsa = activationServer.generateEcServerKeyPair();
            final PrivateKey masterPrivateKeyEcdsa = kpEcdsa.getPrivate();
            final PublicKey masterPublicKeyEcdsa = kpEcdsa.getPublic();

            final KeyPair kpMldsa65 = activationServer.generatePqcServerKeyPair(SharedSecretAlgorithm.EC_P384_ML_L3);
            final PrivateKey masterPrivateKeyMldsa65 = kpMldsa65.getPrivate();
            final PublicKey masterPublicKeyMldsa65 = kpMldsa65.getPublic();

            final KeyPair kpMldsa87 = activationServer.generatePqcServerKeyPair(SharedSecretAlgorithm.EC_P384_ML_L5);
            final PrivateKey masterPrivateKeyMldsa87 = kpMldsa87.getPrivate();
            final PublicKey masterPublicKeyMldsa87 = kpMldsa87.getPublic();

            final byte[] activationSignatureEcdsa = activationServer.generateActivationSignatureEcdsa(activationCode, masterPrivateKeyEcdsa);
            final byte[] activationSignatureMldsa65 = activationServer.generateActivationSignatureMldsa(activationCode, masterPrivateKeyMldsa65);
            final byte[] activationSignatureMldsa87 = activationServer.generateActivationSignatureMldsa(activationCode, masterPrivateKeyMldsa87);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("activationCode", activationCode);
            input.put("masterPrivateKeyEcdsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPrivateKeyToBytes(masterPrivateKeyEcdsa)));
            input.put("masterPublicKeyEcdsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, masterPublicKeyEcdsa)));
            input.put("masterPrivateKeyMldsa65", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPrivateKeyToBytes(masterPrivateKeyMldsa65)));
            input.put("masterPublicKeyMldsa65", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPublicKeyToBytes(masterPublicKeyMldsa65)));
            input.put("masterPrivateKeyMldsa87", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPrivateKeyToBytes(masterPrivateKeyMldsa87)));
            input.put("masterPublicKeyMldsa87", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPublicKeyToBytes(masterPublicKeyMldsa87)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("activationSignatureEcdsa", Base64.getEncoder().encodeToString(activationSignatureEcdsa));
            output.put("activationSignatureMldsa65", Base64.getEncoder().encodeToString(activationSignatureMldsa65));
            output.put("activationSignatureMldsa87", Base64.getEncoder().encodeToString(activationSignatureMldsa87));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for public key fingerprint V4 test for algorithm EC_P384.
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testPublicKeyFingerprintV4EcP384() throws Exception {
        final PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
        final PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
        final IdentifierGenerator generator = new IdentifierGenerator();
        final TestSet testSet = new TestSet("public-key-fingerprint-ec-p384-v4.json", "Fingerprint values for provided public keys, used for visual verification of the successful and untampered public key exchange.");

        int max = 100;
        for (int i = 0; i < max; i++) {
            final KeyPair kpServer = activationServer.generateEcServerKeyPair();
            final KeyPair kpDevice = activationClient.generateDeviceEcKeyPair();
            final ECPublicKey serverPublicKey = (ECPublicKey) kpServer.getPublic();
            final ECPublicKey devicePublicKey = (ECPublicKey) kpDevice.getPublic();

            final String activationId = generator.generateActivationId();

            final String fingerprint = HybridPublicKeyFingerprint.computeEcdsaFingerprint(devicePublicKey, serverPublicKey, activationId, ActivationVersion.VERSION_4);

            final Map<String, String> input = new LinkedHashMap<>();
            input.put("algorithmName", SharedSecretAlgorithm.EC_P384.name());
            input.put("devicePublicKeyEcdsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, devicePublicKey)));
            input.put("serverPublicKeyEcdsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, serverPublicKey)));
            final Map<String, String> output = new LinkedHashMap<>();
            output.put("activationId", activationId);
            output.put("fingerprint", fingerprint);
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for public key fingerprint V4 test for algorithm EC_P384_ML_L3.
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testPublicKeyFingerprintV4EcP384MlL3() throws Exception {
        final PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
        final PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
        final IdentifierGenerator generator = new IdentifierGenerator();
        final TestSet testSet = new TestSet("public-key-fingerprint-ec-p384-ml-l3-v4.json", "Fingerprint values for provided public keys, used for visual verification of the successful and untampered public key exchange.");

        int max = 100;
        for (int i = 0; i < max; i++) {
            final KeyPair kpServerEcdsa = activationServer.generateEcServerKeyPair();
            final KeyPair kpDeviceEcdsa = activationClient.generateDeviceEcKeyPair();
            final KeyPair kpServerMldsa = activationServer.generatePqcServerKeyPair(SharedSecretAlgorithm.EC_P384_ML_L3);
            final KeyPair kpDeviceMldsa = activationClient.generateDevicePqcKeyPair(SharedSecretAlgorithm.EC_P384_ML_L3);
            final ECPublicKey serverPublicKeyEcdsa = (ECPublicKey) kpServerEcdsa.getPublic();
            final ECPublicKey devicePublicKeyEcdsa = (ECPublicKey) kpDeviceEcdsa.getPublic();
            final MLDSAPublicKey serverPublicKeyMldsa = (MLDSAPublicKey) kpServerMldsa.getPublic();
            final MLDSAPublicKey devicePublicKeyMldsa = (MLDSAPublicKey) kpDeviceMldsa.getPublic();

            final String activationId = generator.generateActivationId();

            final String fingerprintPqc = HybridPublicKeyFingerprint.computeHybridFingerprint(SharedSecretAlgorithm.EC_P384_ML_L3, devicePublicKeyEcdsa, devicePublicKeyMldsa, serverPublicKeyEcdsa, serverPublicKeyMldsa, activationId, ActivationVersion.VERSION_4);

            final Map<String, String> input = new LinkedHashMap<>();
            input.put("algorithmName", SharedSecretAlgorithm.EC_P384_ML_L3.name());
            input.put("devicePublicKeyEcdsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, devicePublicKeyEcdsa)));
            input.put("serverPublicKeyEcdsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, serverPublicKeyEcdsa)));
            input.put("devicePublicKeyMldsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPublicKeyToBytes(devicePublicKeyMldsa)));
            input.put("serverPublicKeyMldsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPublicKeyToBytes(serverPublicKeyMldsa)));
            final Map<String, String> output = new LinkedHashMap<>();
            output.put("activationId", activationId);
            output.put("fingerprint", fingerprintPqc);
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for public key fingerprint V4 test for algorithm EC_P384_ML_L5.
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testPublicKeyFingerprintV4EcP384MlL5() throws Exception {
        final PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
        final PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
        final IdentifierGenerator generator = new IdentifierGenerator();
        final TestSet testSet = new TestSet("public-key-fingerprint-ec-p384-ml-l5-v4.json", "Fingerprint values for provided public keys, used for visual verification of the successful and untampered public key exchange.");

        int max = 100;
        for (int i = 0; i < max; i++) {
            final KeyPair kpServerEcdsa = activationServer.generateEcServerKeyPair();
            final KeyPair kpDeviceEcdsa = activationClient.generateDeviceEcKeyPair();
            final KeyPair kpServerMldsa = activationServer.generatePqcServerKeyPair(SharedSecretAlgorithm.EC_P384_ML_L5);
            final KeyPair kpDeviceMldsa = activationClient.generateDevicePqcKeyPair(SharedSecretAlgorithm.EC_P384_ML_L5);
            final ECPublicKey serverPublicKeyEcdsa = (ECPublicKey) kpServerEcdsa.getPublic();
            final ECPublicKey devicePublicKeyEcdsa = (ECPublicKey) kpDeviceEcdsa.getPublic();
            final MLDSAPublicKey serverPublicKeyMldsa = (MLDSAPublicKey) kpServerMldsa.getPublic();
            final MLDSAPublicKey devicePublicKeyMldsa = (MLDSAPublicKey) kpDeviceMldsa.getPublic();

            final String activationId = generator.generateActivationId();

            final String fingerprintPqc = HybridPublicKeyFingerprint.computeHybridFingerprint(SharedSecretAlgorithm.EC_P384_ML_L3, devicePublicKeyEcdsa, devicePublicKeyMldsa, serverPublicKeyEcdsa, serverPublicKeyMldsa, activationId, ActivationVersion.VERSION_4);

            final Map<String, String> input = new LinkedHashMap<>();
            input.put("algorithmName", SharedSecretAlgorithm.EC_P384_ML_L5.name());
            input.put("devicePublicKeyEcdsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, devicePublicKeyEcdsa)));
            input.put("serverPublicKeyEcdsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, serverPublicKeyEcdsa)));
            input.put("devicePublicKeyMldsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPublicKeyToBytes(devicePublicKeyMldsa)));
            input.put("serverPublicKeyMldsa", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPublicKeyToBytes(serverPublicKeyMldsa)));
            final Map<String, String> output = new LinkedHashMap<>();
            output.put("activationId", activationId);
            output.put("fingerprint", fingerprintPqc);
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate JSON file with test vectors for given test set.
     * @param testSet Test set.
     * @throws IOException Thrown when writing into file fails.
     */
    private void writeTestVector(TestSet testSet) throws IOException {
        final FileWriter fw = new FileWriter(testVectorFolder.getAbsolutePath() + File.separator + testSet.getFileName());
        objectMapper.writeValue(fw, testSet);
        fw.close();
    }

}
