/*
 * Copyright 2016 Wultra s.r.o.
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
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.model.TestSet;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.fail;

/**
 * Generate test vectors
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class GenerateVectorDataTest {

    private static File testVectorFolder;
    private static ObjectMapper objectMapper;

    /**
     * Register crypto providers
     */
    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());

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
     * PowerAuth protocol version: 2.0
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testVerifyActivationDataV2() throws Exception {
        String activationOTP;
        String activationIdShort;

        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

        TestSet testSet = new TestSet("verify-activation-data-signature-v2.json", "For \"/pa/activation/prepare\", client needs to be able to verify the signature of the encrypted activation data (version 2 of PowerAuth protocol: short activation ID, activation OTP) using the server master public key, for example when it's stored in the QR code.");

        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        int max = 20;
        for (int i = 0; i < max; i++) {
            activationOTP = new IdentifierGenerator().generateActivationIdShort();
            activationIdShort = new IdentifierGenerator().generateActivationOTP();

            KeyPair kp = activationServer.generateServerKeyPair();
            PrivateKey masterPrivateKey = kp.getPrivate();
            PublicKey masterPublicKey = kp.getPublic();

            byte[] activationSignature = activationServer.generateActivationSignature(activationIdShort, activationOTP, masterPrivateKey);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("activationIdShort", activationIdShort);
            input.put("activationOtp", activationOTP);
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
     * PowerAuth protocol version: 2.0
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testEncryptDevicePublicKeyV2() throws Exception {
        PowerAuthClientActivation activation = new PowerAuthClientActivation();

        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        TestSet testSet = new TestSet("encrypt-device-public-key-v2.json", "For \"/pa/activation/prepare\", client needs to be able to encrypt the public key using activation OTP, activation short ID and activation nonce. (activationIdShort, activationOtp, activationNonce, publicDeviceKey) => cPublicDeviceKey");

        KeyPair masterKeyPair = new KeyGenerator().generateKeyPair();

        int max = 20;
        for (int i = 0; i < max; i++) {
            String activationOTP = new IdentifierGenerator().generateActivationIdShort();
            String activationIdShort = new IdentifierGenerator().generateActivationOTP();
            byte[] activationNonce = activation.generateActivationNonce();
            PublicKey publicKey = new KeyGenerator().generateKeyPair().getPublic();
            byte[] applicationKey = new KeyGenerator().generateRandomBytes(16);
            byte[] applicationSecret = new KeyGenerator().generateRandomBytes(16);

            KeyPair ephemeralKeyPair = new KeyGenerator().generateKeyPair();

            byte[] cDevicePublicKey = activation.encryptDevicePublicKey(publicKey, ephemeralKeyPair.getPrivate(), masterKeyPair.getPublic(), activationOTP, activationIdShort, activationNonce);
            byte[] applicationSignature = activation.computeApplicationSignature(activationIdShort, activationNonce, cDevicePublicKey, applicationKey, applicationSecret);

            Map<String, String> input = new LinkedHashMap<>();
            input.put("activationIdShort", activationIdShort);
            input.put("activationOtp", activationOTP);
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
     * PowerAuth protocol version: 2.0 and 3.0
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testMasterKeyDerivation() throws Exception {

        PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

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
     * PowerAuth protocol version: 2.0 and 3.0
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testDerivedKeyDerivation() throws Exception {

        PowerAuthClientActivation activationClient = new PowerAuthClientActivation();
        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        TestSet testSet = new TestSet("compute-derived-keys.json", "For \"/pa/activation/prepare\", client needs to be able to derive standard PowerAuth 2.0 keys from master shared secret key (masterSecretKey) => (signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey, transportKey, vaultEncryptionKey).");

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
     * PowerAuth protocol version: 2.0
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testActivationAcceptV2() throws Exception {
        String activationOTP;
        String activationIdShort;
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

            activationIdShort = new IdentifierGenerator().generateActivationIdShort();
            activationOTP = new IdentifierGenerator().generateActivationOTP();
            activationNonce = activationServer.generateActivationNonce();

            KeyPair kp = activationClient.generateDeviceKeyPair();
            devicePrivateKey = kp.getPrivate();
            devicePublicKey = kp.getPublic();

            kp = activationServer.generateServerKeyPair();
            serverPublicKey = kp.getPublic();

            kp = activationServer.generateServerKeyPair();
            ephemeralPrivateKey = kp.getPrivate();
            ephemeralPublicKey = kp.getPublic();

            cServerPublicKey = activationServer.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOTP, activationIdShort, activationNonce);
            CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

            Map<String, String> input = new LinkedHashMap<>();
            input.put("activationIdShort", activationIdShort);
            input.put("activationOtp", activationOTP);
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
     * PowerAuth protocol version: 2.0
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testVerifyServerPublicKeySignatureV2() throws Exception {
        String activationId;
        String activationOTP;
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
            activationIdShort = new IdentifierGenerator().generateActivationIdShort();
            activationOTP = new IdentifierGenerator().generateActivationOTP();
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

            cServerPublicKey = activationServer.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOTP, activationIdShort, activationNonce);
            byte[] cServerPublicKeySignature = activationServer.computeServerDataSignature(activationId, cServerPublicKey, masterPrivateKey);

            CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

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
     * Generate test data for signature validation.
     *
     * PowerAuth protocol version: 2.0
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testSignatureValidationV2() throws Exception {

        TestSet testSet = new TestSet("signatures-v2.json", "Client must be able to compute PowerAuth 2.0 signature (using 1FA, 2FA, 3FA signature keys) based on given data, counter and signature type");

        int max = 5;
        int keyMax = 2;
        int ctrMax = 10;
        int dataMax = 256;
        for (int j = 0; j < max; j++) {

            // Prepare data
            KeyGenerator keyGenerator = new KeyGenerator();
            CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

            KeyPair serverKeyPair = keyGenerator.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
            PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();

            PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
            PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();

            for (int i = 0; i < keyMax; i++) {

                // compute data signature
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                SecretKey signaturePossessionKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                SecretKey signatureKnowledgeKey = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                SecretKey signatureBiometryKey = clientKeyFactory.generateClientSignatureBiometryKey(masterClientKey);

                for (int ctr = 0; ctr < ctrMax; ctr++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Collections.singletonList(signaturePossessionKey), ctr);
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

                for (int ctr = 0; ctr < ctrMax; ctr++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), ctr);
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

                for (int ctr = 0; ctr < ctrMax; ctr++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), ctr);
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
     * PowerAuth protocol version: 3.0
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testSignatureValidationV3() throws Exception {

        TestSet testSet = new TestSet("signatures-v3.json", "Client must be able to compute PowerAuth 3.0 signature (using 1FA, 2FA, 3FA signature keys) based on given data, counter and signature type");

        int max = 5;
        int keyMax = 2;
        int signatureCount = 10;
        int dataMax = 256;
        for (int j = 0; j < max; j++) {

            // Prepare data
            KeyGenerator keyGenerator = new KeyGenerator();
            CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

            KeyPair serverKeyPair = keyGenerator.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
            PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();

            PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
            PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();

            HashBasedCounter hashBasedCounter = new HashBasedCounter();

            for (int i = 0; i < keyMax; i++) {

                // compute data signature
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                SecretKey signaturePossessionKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                SecretKey signatureKnowledgeKey = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                SecretKey signatureBiometryKey = clientKeyFactory.generateClientSignatureBiometryKey(masterClientKey);

                byte[] counter = hashBasedCounter.init();

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Collections.singletonList(signaturePossessionKey), counter);
                    String signatureType = "possession";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counterData", BaseEncoding.base64().encode(counter));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    counter = hashBasedCounter.next(counter);
                }

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), counter);
                    String signatureType = "possession_knowledge";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counter", BaseEncoding.base64().encode(counter));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    counter = hashBasedCounter.next(counter);
                }

                for (int k = 0; k < signatureCount; k++) {

                    // generate random data
                    byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * dataMax));

                    String signature = clientSignature.signatureForData(data, Arrays.asList(signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey), counter);
                    String signatureType = "possession_knowledge_biometry";

                    Map<String, String> input = new LinkedHashMap<>();
                    input.put("signaturePossessionKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signaturePossessionKey)));
                    input.put("signatureKnowledgeKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureKnowledgeKey)));
                    input.put("signatureBiometryKey", BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureBiometryKey)));
                    input.put("signatureType", signatureType);
                    input.put("counter", BaseEncoding.base64().encode(counter));
                    input.put("data", BaseEncoding.base64().encode(data));
                    Map<String, String> output = new LinkedHashMap<>();
                    output.put("signature", signature);
                    testSet.addData(input, output);

                    counter = hashBasedCounter.next(counter);
                }
            }
        }
        writeTestVector(testSet);
    }

    /**
     * Generate test data for public key fingerprint test.
     *
     * PowerAuth protocol version: 2.0 and 3.0
     *
     * @throws Exception In case any unknown error occurs.
     */
    @Test
    public void testPublicKeyFingerprint() throws Exception {

        PowerAuthServerActivation activationServer = new PowerAuthServerActivation();

        TestSet testSet = new TestSet("public-key-fingerprint.json", "Fingerprint values for provided public keys, used for visual verification of the successful and untampered public key exchange.");

        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        int max = 100;
        for (int i = 0; i < max; i++) {
            KeyPair kp = activationServer.generateServerKeyPair();
            ECPublicKey publicKey = (ECPublicKey) kp.getPublic();

            final String fingerprint = ECPublicKeyFingerprint.compute(publicKey);

            // Replicate the key normalization for the testing purposes.
            final BigInteger x = publicKey.getW().getAffineX();
            byte[] devicePublicKeyBytes = x.toByteArray();
            if (devicePublicKeyBytes[0] == 0x00) {
                devicePublicKeyBytes = Arrays.copyOfRange(devicePublicKeyBytes, 1, 33);
            }

            Map<String, String> input = new LinkedHashMap<>();
            input.put("publicKey", BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(publicKey)));
            Map<String, String> output = new LinkedHashMap<>();
            output.put("publicKeyCoordX", BaseEncoding.base64().encode(devicePublicKeyBytes));
            output.put("fingerprint", fingerprint);
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
        FileWriter fw = new FileWriter(testVectorFolder.getAbsolutePath() + File.separator + testSet.getFileName());
        objectMapper.writeValue(fw, testSet);
        fw.close();
    }

}
