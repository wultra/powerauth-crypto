/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.config.DecimalSignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.crypto.lib.model.ActivationVersion;
import io.getlime.security.powerauth.crypto.lib.util.model.TestSet;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Generate test vectors
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class GenerateVectorDataTest {

    private static File testVectorFolder;
    private static ObjectMapper objectMapper;

    private final KeyConvertor keyConvertor = new KeyConvertor();

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
     * Generate test data for activation data signature.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testVerifyActivationDataV2() throws Exception {
        String activationCode;
        String activationIdShort;
        String activationOtp;

        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

        TestSet testSet = new TestSet("verify-activation-data-signature-v2.json", "For \"/pa/activation/prepare\", client needs to be able to verify the signature of the encrypted activation data (version 2 of PowerAuth protocol: short activation ID, activation OTP) using the server master public key, for example when it's stored in the QR code.");

        int max = 20;
        for (int i = 0; i < max; i++) {
            activationCode = new IdentifierGenerator().generateActivationCode();
            activationIdShort = activationCode.substring(0, 11);
            activationOtp = activationCode.substring(12);

            KeyPair kp = activationServer.generateServerKeyPair();
            PrivateKey masterPrivateKey = kp.getPrivate();
            PublicKey masterPublicKey = kp.getPublic();

            byte[] activationSignature = activationServer.generateActivationSignature(activationCode, masterPrivateKey);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("activationIdShort", activationIdShort);
            input.put("activationOtp", activationOtp);
            input.put("masterPrivateKey", BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(masterPrivateKey)));
            input.put("masterPublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(masterPublicKey)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("activationSignature", BaseEncoding.base64().encode(activationSignature));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for activation data signature.
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testVerifyActivationDataV3() throws Exception {
        String activationCode;

        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

        TestSet testSet = new TestSet("verify-activation-data-signature-v3.json", "For \"/pa/activation/prepare\", client needs to be able to verify the signature of the encrypted activation data (for version 3 of PowerAuth protocol: activation code) using the server master public key, for example when it's stored in the QR code.");

        IdentifierGenerator identifierGenerator = new IdentifierGenerator();

        int max = 20;
        for (int i = 0; i < max; i++) {
            activationCode = identifierGenerator.generateActivationCode();

            KeyPair kp = activationServer.generateServerKeyPair();
            PrivateKey masterPrivateKey = kp.getPrivate();
            PublicKey masterPublicKey = kp.getPublic();

            byte[] activationSignature = activationServer.generateActivationSignature(activationCode, masterPrivateKey);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("activationCode", activationCode);
            input.put("masterPrivateKey", BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(masterPrivateKey)));
            input.put("masterPublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(masterPublicKey)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("activationSignature", BaseEncoding.base64().encode(activationSignature));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for public key encryption.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testEncryptDevicePublicKeyV2() throws Exception {
        PowerAuthClientActivation activation = new PowerAuthClientActivation();

        TestSet testSet = new TestSet("encrypt-device-public-key-v2.json", "For \"/pa/activation/prepare\", client needs to be able to encrypt the public key using activation OTP, activation short ID and activation nonce. (activationIdShort, activationOtp, activationNonce, publicDeviceKey) => cPublicDeviceKey");

        KeyPair masterKeyPair = new KeyGenerator().generateKeyPair();

        int max = 20;
        for (int i = 0; i < max; i++) {
            String activationCode = new IdentifierGenerator().generateActivationCode();
            String activationIdShort = activationCode.substring(0, 11);
            String activationOtp = activationCode.substring(12);
            byte[] activationNonce = activation.generateActivationNonce();
            PublicKey publicKey = new KeyGenerator().generateKeyPair().getPublic();
            byte[] applicationKey = new KeyGenerator().generateRandomBytes(16);
            byte[] applicationSecret = new KeyGenerator().generateRandomBytes(16);

            KeyPair ephemeralKeyPair = new KeyGenerator().generateKeyPair();

            byte[] cDevicePublicKey = activation.encryptDevicePublicKey(publicKey, ephemeralKeyPair.getPrivate(), masterKeyPair.getPublic(), activationOtp, activationIdShort, activationNonce);
            byte[] applicationSignature = activation.computeApplicationSignature(activationIdShort, activationNonce, cDevicePublicKey, applicationKey, applicationSecret);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("activationIdShort", activationIdShort);
            input.put("activationOtp", activationOtp);
            input.put("activationNonce", BaseEncoding.base64().encode(activationNonce));
            input.put("masterPublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(masterKeyPair.getPublic())));
            input.put("ephemeralPrivateKey", BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(ephemeralKeyPair.getPrivate())));
            input.put("applicationKey", BaseEncoding.base64().encode(applicationKey));
            input.put("applicationSecret", BaseEncoding.base64().encode(applicationSecret));
            input.put("devicePublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(publicKey)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("cDevicePublicKey", BaseEncoding.base64().encode(cDevicePublicKey));
            output.put("applicationSignature", BaseEncoding.base64().encode(applicationSignature));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for master key derivation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     *     <li>3.0</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testMasterKeyDerivation() throws Exception {

        PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

        TestSet testSet = new TestSet("compute-master-secret-key.json", "For \"/pa/activation/prepare\", client needs to be able to compute the master shared secret key from its private key and server's public key (devicePrivateKey, serverPublicKey) => masterSecretKey <= (serverPrivateKey, devicePublicKey).");

        int max = 20;
        for (int i = 0; i < max; i++) {
            KeyPair deviceKeyPair = activationClient.generateDeviceKeyPair();
            KeyPair serverKeyPair = activationServer.generateServerKeyPair();
            SecretKey masterSecretKey = new KeyGenerator().computeSharedKey(deviceKeyPair.getPrivate(), serverKeyPair.getPublic());

            Map<String, String> input = new LinkedHashMap<>();
            input.put("devicePrivateKey", BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(deviceKeyPair.getPrivate())));
            input.put("devicePublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic())));
            input.put("serverPrivateKey", BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(serverKeyPair.getPrivate())));
            input.put("serverPublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(serverKeyPair.getPublic())));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("masterSecretKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterSecretKey)));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for key derivation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     *     <li>3.0</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testDerivedKeyDerivation() throws Exception {

        PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

        TestSet testSet = new TestSet("compute-derived-keys.json", "For \"/pa/activation/prepare\", client needs to be able to derive standard PowerAuth keys from master shared secret key (masterSecretKey) => (signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey, transportKey, vaultEncryptionKey).");

        int max = 20;

        for (int i = 0; i < max; i++) {
            KeyPair deviceKeyPair = activationClient.generateDeviceKeyPair();
            KeyPair serverKeyPair = activationServer.generateServerKeyPair();
            SecretKey masterSecretKey = new KeyGenerator().computeSharedKey(deviceKeyPair.getPrivate(), serverKeyPair.getPublic());

            PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();

            Map<String, String> input = new LinkedHashMap<>();
            input.put("masterSecretKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterSecretKey)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateClientSignaturePossessionKey(masterSecretKey))));
            output.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateClientSignatureKnowledgeKey(masterSecretKey))));
            output.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateClientSignatureBiometryKey(masterSecretKey))));
            output.put("transportKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateServerTransportKey(masterSecretKey))));
            output.put("vaultEncryptionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(keyFactory.generateServerEncryptedVaultKey(masterSecretKey))));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for decrypting server public key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     *@throws Exception In case any unknown error occurs.
     */
    @Test
    public void testActivationAcceptV2() throws Exception {
        String activationCode;
        String activationIdShort;
        String activationOtp;
        byte[] activationNonce;
        PublicKey serverPublicKey;
        byte[] cServerPublicKey;

        PublicKey devicePublicKey;
        PrivateKey devicePrivateKey;

        PublicKey ephemeralPublicKey;
        PrivateKey ephemeralPrivateKey;

        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
        PowerAuthClientActivation activationClient = new PowerAuthClientActivation();

        TestSet testSet = new TestSet("decrypt-server-public-key-v2.json", "For \"/pa/activation/prepare\", client needs to be able to decrypt the server public key using activation OTP, activation short ID, activation nonce, ephemeral public key and a device private key.");

        int max = 20;
        for (int i = 0; i < max; i++) {

            activationCode = new IdentifierGenerator().generateActivationCode();
            activationIdShort = activationCode.substring(0, 11);
            activationOtp = activationCode.substring(12);
            activationNonce = activationServer.generateActivationNonce();

            KeyPair kp = activationClient.generateDeviceKeyPair();
            devicePrivateKey = kp.getPrivate();
            devicePublicKey = kp.getPublic();

            kp = activationServer.generateServerKeyPair();
            serverPublicKey = kp.getPublic();

            kp = activationServer.generateServerKeyPair();
            ephemeralPrivateKey = kp.getPrivate();
            ephemeralPublicKey = kp.getPublic();

            cServerPublicKey = activationServer.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOtp, activationIdShort, activationNonce);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("activationIdShort", activationIdShort);
            input.put("activationOtp", activationOtp);
            input.put("activationNonce", BaseEncoding.base64().encode(activationNonce));
            input.put("devicePrivateKey", BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
            input.put("devicePublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));
            input.put("encryptedServerPublicKey", BaseEncoding.base64().encode(cServerPublicKey));
            input.put("ephemeralPublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(ephemeralPublicKey)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("serverPublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(serverPublicKey)));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for verifying server response data.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testVerifyServerPublicKeySignatureV2() throws Exception {
        String activationId;
        String activationCode;
        String activationOtp;
        String activationIdShort;
        byte[] activationNonce;
        PublicKey serverPublicKey;
        byte[] cServerPublicKey;
        PublicKey devicePublicKey;
        PrivateKey ephemeralPrivateKey;

        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
        PowerAuthClientActivation activationClient = new PowerAuthClientActivation();

        TestSet testSet = new TestSet("verify-encrypted-server-public-key-signature-v2.json", "For \"/pa/activation/prepare\", client needs to be able to verify the signature of the encrypted server public key using the server master public key.");

        int max = 20;
        for (int i = 0; i < max; i++) {

            activationId = new IdentifierGenerator().generateActivationId();
            activationCode = new IdentifierGenerator().generateActivationCode();
            activationIdShort = activationCode.substring(0, 11);
            activationOtp = activationCode.substring(12);
            activationNonce = activationServer.generateActivationNonce();

            KeyPair kp = activationClient.generateDeviceKeyPair();
            devicePublicKey = kp.getPublic();

            kp = activationServer.generateServerKeyPair();
            serverPublicKey = kp.getPublic();

            kp = activationServer.generateServerKeyPair();
            ephemeralPrivateKey = kp.getPrivate();

            kp = activationServer.generateServerKeyPair();
            PrivateKey masterPrivateKey = kp.getPrivate();
            PublicKey masterPublicKey = kp.getPublic();

            cServerPublicKey = activationServer.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOtp, activationIdShort, activationNonce);
            byte[] cServerPublicKeySignature = activationServer.computeServerDataSignature(activationId, cServerPublicKey, masterPrivateKey);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("activationId", activationId);
            input.put("encryptedServerPublicKey", BaseEncoding.base64().encode(cServerPublicKey));
            input.put("masterServerPrivateKey", BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(masterPrivateKey)));
            input.put("masterServerPublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(masterPublicKey)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("encryptedServerPublicKeySignature", BaseEncoding.base64().encode(cServerPublicKeySignature));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for signature validation
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testSignatureValidationV2() throws Exception {

        TestSet testSet = new TestSet("signatures-v2.json", "Client must be able to compute PowerAuth signature (using 1FA, 2FA, 3FA signature keys) based on given data, counter and signature type");

        int max = 5;
        int key_max = 2;
        int ctr_max = 10;
        int data_max = 256;
        for (int j = 0; j < max; j++) {

            // Prepare data
            KeyGenerator keyGenerator = new KeyGenerator();

            KeyPair serverKeyPair = keyGenerator.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
            PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();

            final PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion("2.0");
            SignatureConfiguration signatureConfiguration = SignatureConfiguration.forFormat(signatureFormat);
            PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
            PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();

            for (int i = 0; i < key_max; i++) {

                // compute data signature
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                SecretKey signaturePossessionKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                SecretKey signatureKnowledgeKey = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                SecretKey signatureBiometryKey = clientKeyFactory.generateClientSignatureBiometryKey(masterClientKey);

                for (int ctr = 0; ctr < ctr_max; ctr++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * data_max));

                    byte[] ctrData = ByteBuffer.allocate(16).putLong(8, ctr).array();
                    String signature = clientSignature.signatureForData(data, Collections.singletonList(signaturePossessionKey), ctrData, signatureConfiguration);
                    String signatureType = "possession";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counter", String.valueOf(ctr));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);
                }

                for (int ctr = 0; ctr < ctr_max; ctr++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * data_max));

                    byte[] ctrData = ByteBuffer.allocate(16).putLong(8, ctr).array();
                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), ctrData, signatureConfiguration);
                    String signatureType = "possession_knowledge";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counter", String.valueOf(ctr));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);
                }

                for (int ctr = 0; ctr < ctr_max; ctr++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * data_max));

                    byte[] ctrData = ByteBuffer.allocate(16).putLong(8, ctr).array();
                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData, signatureConfiguration);
                    String signatureType = "possession_knowledge_biometry";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counter", String.valueOf(ctr));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);
                }
            }
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for signature validation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testSignatureValidationV3() throws Exception {

        TestSet testSet = new TestSet("signatures-v3.json", "Client must be able to compute PowerAuth signature (using 1FA, 2FA, 3FA signature keys) based on given data, counter and signature type");

        int max = 5;
        int keyMax = 2;
        int signatureCount = 10;
        int dataMax = 256;
        for (int j = 0; j < max; j++) {

            // Prepare data
            KeyGenerator keyGenerator = new KeyGenerator();

            KeyPair serverKeyPair = keyGenerator.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
            PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();

            final PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion("3.0");
            SignatureConfiguration signatureConfiguration = SignatureConfiguration.forFormat(signatureFormat);
            PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
            PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();

            HashBasedCounter hashBasedCounter = new HashBasedCounter();

            for (int i = 0; i < keyMax; i++) {

                // compute data signature
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                SecretKey signaturePossessionKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                SecretKey signatureKnowledgeKey = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                SecretKey signatureBiometryKey = clientKeyFactory.generateClientSignatureBiometryKey(masterClientKey);

                byte[] ctrData = hashBasedCounter.init();

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Collections.singletonList(signaturePossessionKey), ctrData, signatureConfiguration);
                    String signatureType = "possession";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counterData", BaseEncoding.base64().encode(ctrData));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    ctrData = hashBasedCounter.next(ctrData);
                }

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), ctrData, signatureConfiguration);
                    String signatureType = "possession_knowledge";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counterData", BaseEncoding.base64().encode(ctrData));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    ctrData = hashBasedCounter.next(ctrData);
                }

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData, signatureConfiguration);
                    String signatureType = "possession_knowledge_biometry";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counterData", BaseEncoding.base64().encode(ctrData));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    ctrData = hashBasedCounter.next(ctrData);
                }
            }
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for signature validation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.1</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testSignatureValidationV31() throws Exception {

        TestSet testSet = new TestSet("signatures-v31.json", "Client must be able to compute PowerAuth signature (using 1FA, 2FA, 3FA signature keys) based on given data, counter and signature type");

        int max = 5;
        int keyMax = 2;
        int signatureCount = 10;
        int dataMax = 256;
        for (int j = 0; j < max; j++) {

            // Prepare data
            KeyGenerator keyGenerator = new KeyGenerator();

            KeyPair serverKeyPair = keyGenerator.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
            PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();

            final PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion("3.1");
            SignatureConfiguration signatureConfiguration = SignatureConfiguration.forFormat(signatureFormat);
            PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
            PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();

            HashBasedCounter hashBasedCounter = new HashBasedCounter();

            for (int i = 0; i < keyMax; i++) {

                // compute data signature
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                SecretKey signaturePossessionKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                SecretKey signatureKnowledgeKey = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                SecretKey signatureBiometryKey = clientKeyFactory.generateClientSignatureBiometryKey(masterClientKey);

                byte[] ctrData = hashBasedCounter.init();

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Collections.singletonList(signaturePossessionKey), ctrData, signatureConfiguration);
                    String signatureType = "possession";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counterData", BaseEncoding.base64().encode(ctrData));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    ctrData = hashBasedCounter.next(ctrData);
                }

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), ctrData, signatureConfiguration);
                    String signatureType = "possession_knowledge";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counterData", BaseEncoding.base64().encode(ctrData));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    ctrData = hashBasedCounter.next(ctrData);
                }

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctrData, signatureConfiguration);
                    String signatureType = "possession_knowledge_biometry";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counterData", BaseEncoding.base64().encode(ctrData));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    ctrData = hashBasedCounter.next(ctrData);
                }
            }
        }
        writeTestVector(testSet);
    }

    @Test
    public void testSignatureOfflineValidation() throws Exception {

        TestSet testSet = new TestSet("signatures-offline.json", "Client must be able to compute PowerAuth offline signature (using 1FA, 2FA signature keys) based on given data, counter and signature type");

        int min = 4;
        int max = 9;
        int keyMax = 2;
        int signatureCount = 10;
        int dataMax = 256;
        for (int j = min; j < max; j++) {

            // Prepare data
            KeyGenerator keyGenerator = new KeyGenerator();

            KeyPair serverKeyPair = keyGenerator.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
            PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();

            SignatureConfiguration signatureConfiguration = SignatureConfiguration.decimal();
            PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
            PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();

            HashBasedCounter hashBasedCounter = new HashBasedCounter();

            for (int i = 0; i < keyMax; i++) {

                // compute data signature
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                SecretKey signaturePossessionKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                SecretKey signatureKnowledgeKey = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                SecretKey signatureBiometryKey = clientKeyFactory.generateClientSignatureBiometryKey(masterClientKey);

                byte[] ctrData = hashBasedCounter.init();

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Collections.singletonList(signaturePossessionKey), ctrData, signatureConfiguration);
                    String signatureType = "possession";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("signatureComponentLength", String.valueOf(j));
                    input.put("counterData", BaseEncoding.base64().encode(ctrData));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    ctrData = hashBasedCounter.next(ctrData);
                }

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), ctrData, signatureConfiguration);
                    String signatureType = "possession_knowledge";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("signatureComponentLength", String.valueOf(j));
                    input.put("counterData", BaseEncoding.base64().encode(ctrData));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    ctrData = hashBasedCounter.next(ctrData);
                }

            }
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for public key fingerprint test.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testPublicKeyFingerprintV2() throws Exception {

        PowerAuthClientActivation activationClient = new PowerAuthClientActivation();

        TestSet testSet = new TestSet("public-key-fingerprint-v2.json", "Fingerprint values for provided public keys, used for visual verification of the successful and untampered public key exchange.");

        int max = 100;
        for (int i = 0; i < max; i++) {
            KeyPair kpDevice = activationClient.generateDeviceKeyPair();
            ECPublicKey kpDeviceEC = (ECPublicKey) kpDevice.getPublic();

            final String fingerprint = ECPublicKeyFingerprint.compute(kpDeviceEC, null, null, ActivationVersion.VERSION_2);

            byte[] devicePublicKeyBytes = toByteArray(kpDeviceEC);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("publicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(kpDeviceEC)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("publicKeyCoordX", BaseEncoding.base64().encode(devicePublicKeyBytes));
            output.put("fingerprint", fingerprint);
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for public key fingerprint test.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testPublicKeyFingerprintV3() throws Exception {

        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();
        PowerAuthClientActivation activationClient = new PowerAuthClientActivation();

        IdentifierGenerator generator = new IdentifierGenerator();

        TestSet testSet = new TestSet("public-key-fingerprint-v3.json", "Fingerprint values for provided public keys, used for visual verification of the successful and untampered public key exchange.");

        int max = 100;
        for (int i = 0; i < max; i++) {
            KeyPair kpServer = activationServer.generateServerKeyPair();
            KeyPair kpDevice = activationClient.generateDeviceKeyPair();
            ECPublicKey serverPublicKey = (ECPublicKey) kpServer.getPublic();
            ECPublicKey devicePublicKey = (ECPublicKey) kpDevice.getPublic();

            String activationId = generator.generateActivationId();

            final String fingerprint = ECPublicKeyFingerprint.compute(devicePublicKey, serverPublicKey, activationId, ActivationVersion.VERSION_3);

            byte[] devicePublicKeyBytes = toByteArray(devicePublicKey);
            byte[] serverPublicKeyBytes = toByteArray(serverPublicKey);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("devicePublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));
            input.put("serverPublicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(serverPublicKey)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("devicePublicKeyCoordX", BaseEncoding.base64().encode(devicePublicKeyBytes));
            output.put("serverPublicKeyCoordX", BaseEncoding.base64().encode(serverPublicKeyBytes));
            output.put("activationId", activationId);
            output.put("fingerprint", fingerprint);
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for IV derivation for activation status blob symmetric encryption.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.1</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testDeriveIvForActivationStatusEncryption() throws Exception {

        TestSet testSet = new TestSet("activation-status-blob-iv.json", "Initialization Vectors for activation status blob symmetric encryption.");

        KeyGenerator keyGenerator = new KeyGenerator();
        KeyDerivationUtils keyDerivationUtils = new KeyDerivationUtils();

        for (int i = 0; i < 32; i++) {
            byte[] transportKey = keyGenerator.generateRandomBytes(16);
            byte[] challenge = keyGenerator.generateRandomBytes(16);
            byte[] nonce = keyGenerator.generateRandomBytes(16);
            byte[] iv = keyDerivationUtils.deriveIvForStatusBlobEncryption(challenge, nonce, keyConvertor.convertBytesToSharedSecretKey(transportKey));
            Map<String, String> input = new LinkedHashMap<>();
            input.put("transportKey", BaseEncoding.base64().encode(transportKey));
            input.put("challenge", BaseEncoding.base64().encode(challenge));
            input.put("nonce", BaseEncoding.base64().encode(nonce));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("iv", BaseEncoding.base64().encode(iv));
            testSet.addData(input, output);
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for status blob encryption.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.1</li>
     * </ul>
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testActivationStatusBlobEncoding() throws Exception {
        TestSet testSet = new TestSet("activation-status-blob-data.json", "Status blob test data.");

        final KeyGenerator keyGenerator = new KeyGenerator();
        final PowerAuthServerActivation activation = new PowerAuthServerActivation();
        final BaseEncoding b64 = BaseEncoding.base64();

        final ActivationStatusBlobInfoBuilder[] testData = {
                new ActivationStatusBlobInfoBuilder().ctrByte(1)  .status(2).currentVersion(2),
                new ActivationStatusBlobInfoBuilder().ctrByte(13) .status(3).ctrLookAhead(33).counterDistance(30),
                new ActivationStatusBlobInfoBuilder().ctrByte(133).status(4).failedAttempts(1),
                new ActivationStatusBlobInfoBuilder().ctrByte(63) .status(5).maxFailedAttempts(10),
                new ActivationStatusBlobInfoBuilder().ctrByte(127).status(3).failedAttempts(5).maxFailedAttempts(10),
                new ActivationStatusBlobInfoBuilder().ctrByte(253).status(3).failedAttempts(6).maxFailedAttempts(6),
                new ActivationStatusBlobInfoBuilder().ctrByte(128).status(4).counterDistance(4),
                new ActivationStatusBlobInfoBuilder().ctrByte(77) .status(5).counterDistance(1)
        };

        for (final ActivationStatusBlobInfoBuilder builder : testData) {

            final SecretKey transportKey = keyGenerator.generateRandomSecretKey();
            final byte[] transportKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(transportKey);
            final byte[] ctrData = keyGenerator.generateRandomBytes(16);
            final byte[] challenge = keyGenerator.generateRandomBytes(16);
            final byte[] nonce = keyGenerator.generateRandomBytes(16);

            // Move hash based counter forward for required counter distance times.
            byte[] ctrDataMoved = ctrData;
            for (int i = 0; i < builder.counterDistance; i++) {
                ctrDataMoved = keyGenerator.convert32Bto16B(Hash.sha256(ctrDataMoved));
            }
            final byte[] ctrDataHash = activation.calculateHashFromHashBasedCounter(ctrDataMoved, transportKey);

            final ActivationStatusBlobInfo info = builder.ctrDataHash(ctrDataHash).build();
            final byte[] encryptedStatusBlob = activation.encryptedStatusBlob(info, challenge, nonce, transportKey);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("transportKey", b64.encode(transportKeyBytes));
            input.put("challenge", b64.encode(challenge));
            input.put("nonce", b64.encode(nonce));
            input.put("ctrData", b64.encode(ctrData));
            input.put("encryptedStatusBlob", BaseEncoding.base64().encode(encryptedStatusBlob));

            Map<String, String> output = builder.toMap();
            testSet.addData(input, output);
        }

        writeTestVector(testSet);
    }

    /**
     * Helper class that helps with ActivationStatusBlobInfo object construction.
     */
    private static class ActivationStatusBlobInfoBuilder {

        final ActivationStatusBlobInfo info;
        int counterDistance;

        ActivationStatusBlobInfoBuilder() {
            info = new ActivationStatusBlobInfo();
            info.setActivationStatus((byte)3);
            info.setCurrentVersion((byte)3);
            info.setUpgradeVersion((byte)3);
            info.setFailedAttempts((byte)0);
            info.setMaxFailedAttempts((byte)5);
            info.setCtrLookAhead((byte)20);
            info.setCtrDataHash(new byte[16]);
            counterDistance = 0;
        }

        ActivationStatusBlobInfoBuilder status(int status) {
            info.setActivationStatus((byte)status);
            return this;
        }

        ActivationStatusBlobInfoBuilder currentVersion(int value) {
            info.setCurrentVersion((byte)value);
            return this;
        }

        ActivationStatusBlobInfoBuilder upgradeVersion(int value) {
            info.setCurrentVersion((byte)value);
            return this;
        }

        ActivationStatusBlobInfoBuilder failedAttempts(int value) {
            info.setFailedAttempts((byte)value);
            return this;
        }

        ActivationStatusBlobInfoBuilder maxFailedAttempts(int value) {
            info.setMaxFailedAttempts((byte)value);
            return this;
        }

        ActivationStatusBlobInfoBuilder ctrLookAhead(int value) {
            info.setCtrLookAhead((byte)value);
            return this;
        }

        ActivationStatusBlobInfoBuilder ctrByte(int value) {
            info.setCtrByte((byte)value);
            return this;
        }

        ActivationStatusBlobInfoBuilder ctrDataHash(byte[] value) {
            info.setCtrDataHash(value);
            return this;
        }

        ActivationStatusBlobInfoBuilder counterDistance(int distance) {
            counterDistance = distance;
            return this;
        }

        /**
         * @return ActivationStatusBlobInfo object constructed from values set to builder.
         */
        ActivationStatusBlobInfo build() {
            return info;
        }

        /**
         * @return Map with values stored in ActivationStatusBlobInfo
         */
        Map<String, String> toMap() {
            final Map<String, String> map = new LinkedHashMap<>();
            map.put("activationStatus", toUnsignedByteString(info.getActivationStatus()));
            map.put("currentVersion", toUnsignedByteString(info.getCurrentVersion()));
            map.put("upgradeVersion", toUnsignedByteString(info.getUpgradeVersion()));
            map.put("failedAttempts", toUnsignedByteString(info.getFailedAttempts()));
            map.put("maxFailedAttempts", toUnsignedByteString(info.getMaxFailedAttempts()));
            map.put("ctrLookAhead", toUnsignedByteString(info.getCtrLookAhead()));
            map.put("ctrByte", toUnsignedByteString(info.getCtrByte()));
            map.put("ctrDataHash", BaseEncoding.base64().encode(info.getCtrDataHash()));
            map.put("counterDistance", String.valueOf(counterDistance));
            return map;
        }

        /**
         * Helper function that converts byte to its unsigned string representation. For example, {@code -1} should be
         * converted to {@code "255"}.
         * @param value Byte to convert.
         * @return String with unsigned value of byte.
         */
        private String toUnsignedByteString(byte value) {
            int intValue = value & 0xFF;
            return String.valueOf(intValue);
        }
    }

    /**
     * Convert EC public key to byte array.
     *
     * @param publicKey EC public key.
     * @return Byte array representation of public key.
     */
    private byte[] toByteArray(ECPublicKey publicKey) {
        // Replicate the key normalization for the testing purposes.
        final BigInteger x = publicKey.getW().getAffineX();
        byte[] publicKeyBytes = x.toByteArray();
        if (publicKeyBytes[0] == 0x00) {
            publicKeyBytes = Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length);
        }
        return publicKeyBytes;
    }

    /**
     * Generate JSON file with test vectors for given test set.
     * @param testSet Test set.
     * @throws IOException Thrown when writing into file fails.
     */
    private void writeTestVector(TestSet testSet) throws IOException {
        FileWriter fw = new FileWriter(testVectorFolder.getAbsolutePath() + File.separator + testSet.getFileName());
        objectMapper.writeValue(fw, testSet);
        fw.close();
    }

}
