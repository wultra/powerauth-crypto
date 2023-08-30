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
package io.getlime.security.powerauth.crypto.signature;

import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.config.DecimalSignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.crypto.server.signature.PowerAuthServerSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for PowerAuth signature calculation and validation.
 * 
 * @author Petr Dvorak
 *
 */
public class PowerAuthSignatureTest {

    private final KeyConvertor keyConvertor = new KeyConvertor();

	/**
	 * Register crypto providers. 
	 */
	@BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test of signature generation and validation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @throws java.lang.Exception If the test fails.
     */
    @Test
    public void testSignatureForDataV3() throws Exception {
        System.out.println("# PowerAuth Signature");
        System.out.println();

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        System.out.println("## Server Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(serverPrivateKey)));
        System.out.println("## Server Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(serverPublicKey)));

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        System.out.println("## Device Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
        System.out.println("## Device Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));

        final PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion("3.0");
        assertEquals(PowerAuthSignatureFormat.DECIMAL, signatureFormat);
        final SignatureConfiguration signatureConfiguration = SignatureConfiguration.forFormat(signatureFormat);
        PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
        PowerAuthServerSignature serverSignature = new PowerAuthServerSignature();

        PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();
        PowerAuthServerKeyFactory serverKeyFactory = new PowerAuthServerKeyFactory();

        HashBasedCounter ctrGenerator = new HashBasedCounter();
        byte[] ctrData = ctrGenerator.init();

        for (int i = 0; i < 5; i++) {

            System.out.println();
            System.out.println("# PowerAuth Signature Test - Round " + i);
            System.out.println("# 1FA ====");

            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKey)));

                String signature = clientSignature.signatureForData(data, Collections.singletonList(signatureClientKey), ctrData, signatureConfiguration);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKey = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKey)));
                assertEquals(signatureClientKey, signatureServerKey);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Collections.singletonList(signatureServerKey), ctrData, signatureConfiguration);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

                ctrData = ctrGenerator.next(ctrData);
            }

            System.out.println("# 2FA ====");
            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKeyPossession = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key - Possession: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyPossession)));
                SecretKey signatureClientKeyKnowledge = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                System.out.println("### Client Signature Key - Knowledge:  " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyKnowledge)));

                String signature = clientSignature.signatureForData(data, Arrays.asList(signatureClientKeyPossession, signatureClientKeyKnowledge), ctrData, signatureConfiguration);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKeyPossession = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyPossession)));
                assertEquals(signatureClientKeyPossession, signatureServerKeyPossession);
                SecretKey signatureServerKeyKnowledge = serverKeyFactory.generateServerSignatureKnowledgeKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyKnowledge)));
                assertEquals(signatureClientKeyKnowledge, signatureServerKeyKnowledge);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Arrays.asList(signatureServerKeyPossession, signatureClientKeyKnowledge), ctrData, signatureConfiguration);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

                ctrData = ctrGenerator.next(ctrData);
            }
        }
    }

    /**
     * Test of signature generation and validation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.1</li>
     *     <li>3.2</li>
     * </ul>
     *
     * @throws java.lang.Exception If the test fails.
     */
    @Test
    public void testSignatureForDataV31Plus() throws Exception {
        System.out.println("# PowerAuth Signature");
        System.out.println();

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        System.out.println("## Server Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(serverPrivateKey)));
        System.out.println("## Server Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(serverPublicKey)));

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        System.out.println("## Device Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
        System.out.println("## Device Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));

        final PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion("3.1");
        assertEquals(PowerAuthSignatureFormat.BASE64, signatureFormat);
        final SignatureConfiguration signatureConfiguration = SignatureConfiguration.forFormat(signatureFormat);
        PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
        PowerAuthServerSignature serverSignature = new PowerAuthServerSignature();

        PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();
        PowerAuthServerKeyFactory serverKeyFactory = new PowerAuthServerKeyFactory();

        HashBasedCounter ctrGenerator = new HashBasedCounter();
        byte[] ctrData = ctrGenerator.init();

        for (int i = 0; i < 5; i++) {

            System.out.println();
            System.out.println("# PowerAuth Signature Test - Round " + i);
            System.out.println("# 1FA ====");

            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKey)));

                String signature = clientSignature.signatureForData(data, Collections.singletonList(signatureClientKey), ctrData, signatureConfiguration);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKey = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKey)));
                assertEquals(signatureClientKey, signatureServerKey);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Collections.singletonList(signatureServerKey), ctrData, signatureConfiguration);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

                ctrData = ctrGenerator.next(ctrData);
            }

            System.out.println("# 2FA ====");
            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKeyPossession = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key - Possession: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyPossession)));
                SecretKey signatureClientKeyKnowledge = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                System.out.println("### Client Signature Key - Knowledge:  " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyKnowledge)));

                String signature = clientSignature.signatureForData(data, Arrays.asList(signatureClientKeyPossession, signatureClientKeyKnowledge), ctrData, signatureConfiguration);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKeyPossession = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyPossession)));
                assertEquals(signatureClientKeyPossession, signatureServerKeyPossession);
                SecretKey signatureServerKeyKnowledge = serverKeyFactory.generateServerSignatureKnowledgeKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyKnowledge)));
                assertEquals(signatureClientKeyKnowledge, signatureServerKeyKnowledge);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Arrays.asList(signatureServerKeyPossession, signatureClientKeyKnowledge), ctrData, signatureConfiguration);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

                ctrData = ctrGenerator.next(ctrData);
            }
        }
    }

    /**
     * Test of signature generation and validation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.1</li>
     *     <li>3.2</li>
     * </ul>
     *
     * @throws java.lang.Exception If the test fails.
     */
    @Test
    public void testOfflineSignatureForDataV31Plus() throws Exception {
        System.out.println("# PowerAuth Offline Signature");
        System.out.println();

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        System.out.println("## Server Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(serverPrivateKey)));
        System.out.println("## Server Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(serverPublicKey)));

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        System.out.println("## Device Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
        System.out.println("## Device Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));

        final DecimalSignatureConfiguration signatureConfiguration = SignatureConfiguration.decimal();

        PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
        PowerAuthServerSignature serverSignature = new PowerAuthServerSignature();

        PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();
        PowerAuthServerKeyFactory serverKeyFactory = new PowerAuthServerKeyFactory();

        HashBasedCounter ctrGenerator = new HashBasedCounter();
        byte[] ctrData = ctrGenerator.init();

        for (int i = 0; i < 5; i++) {

            System.out.println();
            System.out.println("# PowerAuth Signature Test - Round " + i);
            System.out.println("# 1FA ====");

            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKey)));

                String signature = clientSignature.signatureForData(data, Collections.singletonList(signatureClientKey), ctrData, signatureConfiguration);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKey = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKey)));
                assertEquals(signatureClientKey, signatureServerKey);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Collections.singletonList(signatureServerKey), ctrData, signatureConfiguration);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

                ctrData = ctrGenerator.next(ctrData);
            }

            System.out.println("# 2FA ====");
            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKeyPossession = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key - Possession: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyPossession)));
                SecretKey signatureClientKeyKnowledge = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                System.out.println("### Client Signature Key - Knowledge:  " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyKnowledge)));

                String signature = clientSignature.signatureForData(data, Arrays.asList(signatureClientKeyPossession, signatureClientKeyKnowledge), ctrData, signatureConfiguration);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKeyPossession = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyPossession)));
                assertEquals(signatureClientKeyPossession, signatureServerKeyPossession);
                SecretKey signatureServerKeyKnowledge = serverKeyFactory.generateServerSignatureKnowledgeKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyKnowledge)));
                assertEquals(signatureClientKeyKnowledge, signatureServerKeyKnowledge);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Arrays.asList(signatureServerKeyPossession, signatureClientKeyKnowledge), ctrData, signatureConfiguration);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

                ctrData = ctrGenerator.next(ctrData);
            }

            System.out.println("# 2FA, override component length ====");
            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // Chose length between 4 and 8
                final int componentLength = 4 + j % 5;
                signatureConfiguration.setLength(componentLength);

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKeyPossession = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key - Possession: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyPossession)));
                SecretKey signatureClientKeyKnowledge = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                System.out.println("### Client Signature Key - Knowledge:  " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyKnowledge)));

                String signature = clientSignature.signatureForData(data, Arrays.asList(signatureClientKeyPossession, signatureClientKeyKnowledge), ctrData, signatureConfiguration);

                System.out.println("## Client Signature: " + signature);
                assertEquals(componentLength * 2 + 1, signature.length());

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKeyPossession = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyPossession)));
                assertEquals(signatureClientKeyPossession, signatureServerKeyPossession);
                SecretKey signatureServerKeyKnowledge = serverKeyFactory.generateServerSignatureKnowledgeKey(masterServerKey);
                System.out.println("### Server Signature Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyKnowledge)));
                assertEquals(signatureClientKeyKnowledge, signatureServerKeyKnowledge);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Arrays.asList(signatureServerKeyPossession, signatureClientKeyKnowledge), ctrData, signatureConfiguration);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

                ctrData = ctrGenerator.next(ctrData);
            }
        }
    }

}
