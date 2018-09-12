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
package io.getlime.security.powerauth.crypto.signature;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounterGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.crypto.server.signature.PowerAuthServerSignature;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test for PowerAuth signature calculation and validation.
 * 
 * @author Petr Dvorak
 *
 */
public class PowerAuthSignatureTest {

	/**
	 * Register crypto providers. 
	 */
	@Before
    public void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());
    }

    /**
     * Test of signature generation and validation.
     *
     * PowerAuth protocol version: 2.0
     *
     * @throws java.lang.Exception If the test fails.
     */
    @Test
    public void testSignatureForDataV2() throws Exception {
        System.out.println("# PowerAuth 2.0 Signature");
        System.out.println();

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();
        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        System.out.println("## Server Private Key: " + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(serverPrivateKey)));
        System.out.println("## Server Public Key:  " + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(serverPublicKey)));

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        System.out.println("## Device Private Key: " + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
        System.out.println("## Device Public Key:  " + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));

        PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
        PowerAuthServerSignature serverSignature = new PowerAuthServerSignature();
        
        PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();
        PowerAuthServerKeyFactory serverKeyFactory = new PowerAuthServerKeyFactory();

        for (int i = 0; i < 5; i++) {

            System.out.println();
            System.out.println("# PowerAuth 2.0 Signature Test - Round " + i);
            System.out.println("# 1FA ====");

            for (int ctr = 0; ctr < 20; ctr++) {

                System.out.println();
                System.out.println("## Counter: " + ctr);

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + BaseEncoding.base64().encode(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKey)));

                String signature = clientSignature.signatureForData(data, Collections.singletonList(signatureClientKey), ctr);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKey = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKey)));
                assertEquals(signatureClientKey, signatureServerKey);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Collections.singletonList(signatureServerKey), ctr);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

            }
            
            System.out.println("# 2FA ====");
            for (int ctr = 0; ctr < 20; ctr++) {

                System.out.println();
                System.out.println("## Counter: " + ctr);

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + BaseEncoding.base64().encode(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKeyPossession = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key - Possession: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyPossession)));
                SecretKey signatureClientKeyKnowledge = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                System.out.println("### Client Signature Key - Knowledge:  " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyKnowledge)));

                String signature = clientSignature.signatureForData(data, Arrays.asList(signatureClientKeyPossession, signatureClientKeyKnowledge), ctr);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);
                
                SecretKey signatureServerKeyPossession = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyPossession)));
                assertEquals(signatureClientKeyPossession, signatureServerKeyPossession);
                SecretKey signatureServerKeyKnowledge = serverKeyFactory.generateServerSignatureKnowledgeKey(masterServerKey);
                System.out.println("### Server Signature Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyKnowledge)));
                assertEquals(signatureClientKeyKnowledge, signatureServerKeyKnowledge);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Arrays.asList(signatureServerKeyPossession, signatureClientKeyKnowledge), ctr);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

            }
        }
    }

    /**
     * Test of signature generation and validation.
     *
     * PowerAuth protocol version: 3.0
     *
     * @throws java.lang.Exception If the test fails.
     */
    @Test
    public void testSignatureForDataV3() throws Exception {
        System.out.println("# PowerAuth 3.0 Signature");
        System.out.println();

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();
        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        System.out.println("## Server Private Key: " + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(serverPrivateKey)));
        System.out.println("## Server Public Key:  " + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(serverPublicKey)));

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        System.out.println("## Device Private Key: " + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
        System.out.println("## Device Public Key:  " + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));

        PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
        PowerAuthServerSignature serverSignature = new PowerAuthServerSignature();

        PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();
        PowerAuthServerKeyFactory serverKeyFactory = new PowerAuthServerKeyFactory();

        HashBasedCounterGenerator ctrGenerator = new HashBasedCounterGenerator();
        byte[] ctrData = ctrGenerator.generateInitialValue();

        for (int i = 0; i < 5; i++) {

            System.out.println();
            System.out.println("# PowerAuth 2.0 Signature Test - Round " + i);
            System.out.println("# 1FA ====");

            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + BaseEncoding.base64().encode(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + BaseEncoding.base64().encode(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKey = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKey)));

                String signature = clientSignature.signatureForData(data, Collections.singletonList(signatureClientKey), ctrData);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKey = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKey)));
                assertEquals(signatureClientKey, signatureServerKey);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Collections.singletonList(signatureServerKey), ctrData);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

                ctrData = ctrGenerator.generateNextValue(ctrData);
            }

            System.out.println("# 2FA ====");
            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + BaseEncoding.base64().encode(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + BaseEncoding.base64().encode(data));

                // compute data signature
                System.out.println("## Client Signature Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKeyPossession = clientKeyFactory.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key - Possession: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyPossession)));
                SecretKey signatureClientKeyKnowledge = clientKeyFactory.generateClientSignatureKnowledgeKey(masterClientKey);
                System.out.println("### Client Signature Key - Knowledge:  " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureClientKeyKnowledge)));

                String signature = clientSignature.signatureForData(data, Arrays.asList(signatureClientKeyPossession, signatureClientKeyKnowledge), ctrData);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKeyPossession = serverKeyFactory.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyPossession)));
                assertEquals(signatureClientKeyPossession, signatureServerKeyPossession);
                SecretKey signatureServerKeyKnowledge = serverKeyFactory.generateServerSignatureKnowledgeKey(masterServerKey);
                System.out.println("### Server Signature Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(signatureServerKeyKnowledge)));
                assertEquals(signatureClientKeyKnowledge, signatureServerKeyKnowledge);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Arrays.asList(signatureServerKeyPossession, signatureClientKeyKnowledge), ctrData);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

                ctrData = ctrGenerator.generateNextValue(ctrData);
            }
        }
    }

}
