/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.client.signature;

import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.server.signature.PowerAuthServerSignature;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.io.BaseEncoding;

import static org.junit.Assert.*;

public class PowerAuthSignatureTest {

    public PowerAuthSignatureTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of signature generation and validation.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testSignatureForData() throws Exception {
        System.out.println("# PowerAuth 2.0 Signature");
        System.out.println();

        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();
        KeyConversionUtils keyConversionUtils = new KeyConversionUtils();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        System.out.println("## Server Private Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertPrivateKeyToBytes(serverPrivateKey)));
        System.out.println("## Server Public Key:  " + BaseEncoding.base64().encode(keyConversionUtils.convertPublicKeyToBytes(serverPublicKey)));

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        System.out.println("## Device Private Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertPrivateKeyToBytes(devicePrivateKey)));
        System.out.println("## Device Public Key:  " + BaseEncoding.base64().encode(keyConversionUtils.convertPublicKeyToBytes(devicePublicKey)));

        PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
        PowerAuthServerSignature serverSignature = new PowerAuthServerSignature();

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
                SecretKey masterClientKey = clientSignature.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKey = clientSignature.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(signatureClientKey)));

                String signature = clientSignature.signatureForData(data, Arrays.asList(signatureClientKey), ctr);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverSignature.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey signatureServerKey = serverSignature.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(signatureServerKey)));
                assertEquals(signatureClientKey, signatureServerKey);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Arrays.asList(signatureServerKey), ctr);
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
                SecretKey masterClientKey = clientSignature.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey signatureClientKeyPossession = clientSignature.generateClientSignaturePossessionKey(masterClientKey);
                System.out.println("### Client Signature Key - Possession: " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(signatureClientKeyPossession)));
                SecretKey signatureClientKeyKnowledge = clientSignature.generateClientSignatureKnowledgeKey(masterClientKey);
                System.out.println("### Client Signature Key - Knowledge:  " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(signatureClientKeyKnowledge)));

                String signature = clientSignature.signatureForData(data, Arrays.asList(signatureClientKeyPossession, signatureClientKeyKnowledge), ctr);

                System.out.println("## Client Signature: " + signature);

                // validate data signature
                System.out.println("## Server Signature Key Derivation");

                SecretKey masterServerKey = serverSignature.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);
                
                SecretKey signatureServerKeyPossession = serverSignature.generateServerSignaturePossessionKey(masterServerKey);
                System.out.println("### Server Signature Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(signatureServerKeyPossession)));
                assertEquals(signatureClientKeyPossession, signatureServerKeyPossession);
                SecretKey signatureServerKeyKnowledge = serverSignature.generateServerSignatureKnowledgeKey(masterServerKey);
                System.out.println("### Server Signature Key: " + BaseEncoding.base64().encode(keyConversionUtils.convertSharedSecretKeyToBytes(signatureServerKeyKnowledge)));
                assertEquals(signatureClientKeyKnowledge, signatureServerKeyKnowledge);

                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, Arrays.asList(signatureServerKeyPossession, signatureClientKeyKnowledge), ctr);
                System.out.println("## Signature valid: " + (isSignatureValid ? "TRUE" : "FALSE"));
                assertTrue(isSignatureValid);

            }
        }
    }

}
