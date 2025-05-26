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
package com.wultra.security.powerauth.crypto.authentication;

import com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.client.authentication.PowerAuthClientAuthentication;
import com.wultra.security.powerauth.crypto.lib.config.DecimalAuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthAuthenticationCodeFormat;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import com.wultra.security.powerauth.crypto.server.authentication.PowerAuthServerAuthentication;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
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
 * Test for PowerAuth authentication code calculation and validation.
 * 
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthAuthenticationCodeTest {

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
     * Test of authentication code generation and validation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @throws java.lang.Exception If the test fails.
     */
    @Test
    public void testAuthenticationForDataV3() throws Exception {
        System.out.println("# PowerAuth Authentication");
        System.out.println();

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair(EcCurve.P256);
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        System.out.println("## Server Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(serverPrivateKey)));
        System.out.println("## Server Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(EcCurve.P256, serverPublicKey)));

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair(EcCurve.P256);
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        System.out.println("## Device Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
        System.out.println("## Device Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(EcCurve.P256, devicePublicKey)));

        final PowerAuthAuthenticationCodeFormat format = PowerAuthAuthenticationCodeFormat.getFormatForVersion("3.0");
        assertEquals(PowerAuthAuthenticationCodeFormat.DECIMAL, format);
        final AuthenticationCodeConfiguration authenticationCodeConfiguration = AuthenticationCodeConfiguration.forFormat(format);
        PowerAuthClientAuthentication clientAuth = new PowerAuthClientAuthentication();
        PowerAuthServerAuthentication serverAuth = new PowerAuthServerAuthentication();

        PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();
        PowerAuthServerKeyFactory serverKeyFactory = new PowerAuthServerKeyFactory();

        HashBasedCounter ctrGenerator = new HashBasedCounter("3.0");
        byte[] ctrData = ctrGenerator.init();

        for (int i = 0; i < 5; i++) {

            System.out.println();
            System.out.println("# PowerAuth Authentication Test - Round " + i);
            System.out.println("# 1FA ====");

            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data authentication code
                System.out.println("## Client Authentication Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey clientPossessionKey = clientKeyFactory.generateClientPossessionFactorKey(masterClientKey);
                System.out.println("### Client Authentication Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientPossessionKey)));

                String authenticationCode = clientAuth.computeAuthCode(data, Collections.singletonList(clientPossessionKey), ctrData, authenticationCodeConfiguration);

                System.out.println("## Client Authentication Code: " + authenticationCode);

                // validate authentication code
                System.out.println("## Server Authentication Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey serverPossessionKey = serverKeyFactory.generateServerPossessionFactorKey(masterServerKey);
                System.out.println("### Server Possession Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverPossessionKey)));
                assertEquals(clientPossessionKey, serverPossessionKey);

                boolean isAuthenticationCodeValid = serverAuth.verifyAuthenticationForData(data, authenticationCode, Collections.singletonList(serverPossessionKey), ctrData, authenticationCodeConfiguration);
                System.out.println("## Authentication Code valid: " + (isAuthenticationCodeValid ? "TRUE" : "FALSE"));
                assertTrue(isAuthenticationCodeValid);

                ctrData = ctrGenerator.next(ctrData);
            }

            System.out.println("# 2FA ====");
            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data authentication code
                System.out.println("## Client Authentication Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey clientKeyPossession = clientKeyFactory.generateClientPossessionFactorKey(masterClientKey);
                System.out.println("### Client Factor Key - Possession: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientKeyPossession)));
                SecretKey clientKeyKnowledge = clientKeyFactory.generateClientKnowledgeFactorKey(masterClientKey);
                System.out.println("### Client Factor Key - Knowledge:  " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientKeyKnowledge)));

                String authenticationCode = clientAuth.computeAuthCode(data, Arrays.asList(clientKeyPossession, clientKeyKnowledge), ctrData, authenticationCodeConfiguration);

                System.out.println("## Client Authentication Code: " + authenticationCode);

                // validate authentication code
                System.out.println("## Server Authentication Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey serverKeyPossession = serverKeyFactory.generateServerPossessionFactorKey(masterServerKey);
                System.out.println("### Server Possession Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverKeyPossession)));
                assertEquals(clientKeyPossession, serverKeyPossession);
                SecretKey serverKeyKnowledge = serverKeyFactory.generateServerKnowledgeFactorKey(masterServerKey);
                System.out.println("### Server Knowledge Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverKeyKnowledge)));
                assertEquals(clientKeyKnowledge, serverKeyKnowledge);

                boolean isAuthenticationCodeValid = serverAuth.verifyAuthenticationForData(data, authenticationCode, Arrays.asList(serverKeyPossession, clientKeyKnowledge), ctrData, authenticationCodeConfiguration);
                System.out.println("## Authentication Code valid: " + (isAuthenticationCodeValid ? "TRUE" : "FALSE"));
                assertTrue(isAuthenticationCodeValid);

                ctrData = ctrGenerator.next(ctrData);
            }
        }
    }

    /**
     * Test of authentication code generation and validation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @throws java.lang.Exception If the test fails.
     */
    @Test
    public void testAuthenticationForDataV31Plus() throws Exception {
        System.out.println("# PowerAuth Authentication");
        System.out.println();

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair(EcCurve.P256);
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        System.out.println("## Server Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(serverPrivateKey)));
        System.out.println("## Server Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(EcCurve.P256, serverPublicKey)));

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair(EcCurve.P256);
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        System.out.println("## Device Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
        System.out.println("## Device Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(EcCurve.P256, devicePublicKey)));

        final PowerAuthAuthenticationCodeFormat formatFormat = PowerAuthAuthenticationCodeFormat.getFormatForVersion("3.1");
        assertEquals(PowerAuthAuthenticationCodeFormat.BASE64, formatFormat);
        final AuthenticationCodeConfiguration authenticationCodeConfiguration = AuthenticationCodeConfiguration.forFormat(formatFormat);
        PowerAuthClientAuthentication clientAuth = new PowerAuthClientAuthentication();
        PowerAuthServerAuthentication serverAuth = new PowerAuthServerAuthentication();

        PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();
        PowerAuthServerKeyFactory serverKeyFactory = new PowerAuthServerKeyFactory();

        HashBasedCounter ctrGenerator = new HashBasedCounter("3.1");
        byte[] ctrData = ctrGenerator.init();

        for (int i = 0; i < 5; i++) {

            System.out.println();
            System.out.println("# PowerAuth Authentication Test - Round " + i);
            System.out.println("# 1FA ====");

            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data authentication code
                System.out.println("## Client Authentication Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey clientPossessionKey = clientKeyFactory.generateClientPossessionFactorKey(masterClientKey);
                System.out.println("### Client Authentication Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientPossessionKey)));

                String authenticationCode = clientAuth.computeAuthCode(data, Collections.singletonList(clientPossessionKey), ctrData, authenticationCodeConfiguration);

                System.out.println("## Client Authentication: " + authenticationCode);

                // validate authentication code
                System.out.println("## Server Authentication Code Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey serverPossessionKey = serverKeyFactory.generateServerPossessionFactorKey(masterServerKey);
                System.out.println("### Server Possession Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverPossessionKey)));
                assertEquals(clientPossessionKey, serverPossessionKey);

                boolean isAuthenticationCodeValid = serverAuth.verifyAuthenticationForData(data, authenticationCode, Collections.singletonList(serverPossessionKey), ctrData, authenticationCodeConfiguration);
                System.out.println("## Authentication Code valid: " + (isAuthenticationCodeValid ? "TRUE" : "FALSE"));
                assertTrue(isAuthenticationCodeValid);

                ctrData = ctrGenerator.next(ctrData);
            }

            System.out.println("# 2FA ====");
            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data authentication code
                System.out.println("## Client Authentication Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey clientKeyPossession = clientKeyFactory.generateClientPossessionFactorKey(masterClientKey);
                System.out.println("### Client Key - Possession: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientKeyPossession)));
                SecretKey clientKeyKnowledge = clientKeyFactory.generateClientKnowledgeFactorKey(masterClientKey);
                System.out.println("### Client Key - Knowledge:  " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientKeyKnowledge)));

                String authenticationCode = clientAuth.computeAuthCode(data, Arrays.asList(clientKeyPossession, clientKeyKnowledge), ctrData, authenticationCodeConfiguration);

                System.out.println("## Client Authentication Code: " + authenticationCode);

                // validate authentication code
                System.out.println("## Server Authentication Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey serverKeyPossession = serverKeyFactory.generateServerPossessionFactorKey(masterServerKey);
                System.out.println("### Server Possession Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverKeyPossession)));
                assertEquals(clientKeyPossession, serverKeyPossession);
                SecretKey serverKeyKnowledge = serverKeyFactory.generateServerKnowledgeFactorKey(masterServerKey);
                System.out.println("### Server Knowledge Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverKeyKnowledge)));
                assertEquals(clientKeyKnowledge, serverKeyKnowledge);

                boolean isAuthenticationCodeValid = serverAuth.verifyAuthenticationForData(data, authenticationCode, Arrays.asList(serverKeyPossession, clientKeyKnowledge), ctrData, authenticationCodeConfiguration);
                System.out.println("## Authentication Code valid: " + (isAuthenticationCodeValid ? "TRUE" : "FALSE"));
                assertTrue(isAuthenticationCodeValid);

                ctrData = ctrGenerator.next(ctrData);
            }
        }
    }

    /**
     * Test of authentication code generation and validation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @throws java.lang.Exception If the test fails.
     */
    @Test
    public void testOfflineAuthenticationForDataV31Plus() throws Exception {
        System.out.println("# PowerAuth Offline Authentication");
        System.out.println();

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair(EcCurve.P256);
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        System.out.println("## Server Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(serverPrivateKey)));
        System.out.println("## Server Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(EcCurve.P256, serverPublicKey)));

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair(EcCurve.P256);
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        System.out.println("## Device Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(devicePrivateKey)));
        System.out.println("## Device Public Key:  " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(EcCurve.P256, devicePublicKey)));

        final DecimalAuthenticationCodeConfiguration authenticationCodeConfiguration = AuthenticationCodeConfiguration.decimal();

        PowerAuthClientAuthentication clientAuth = new PowerAuthClientAuthentication();
        PowerAuthServerAuthentication serverAuth = new PowerAuthServerAuthentication();

        PowerAuthClientKeyFactory clientKeyFactory = new PowerAuthClientKeyFactory();
        PowerAuthServerKeyFactory serverKeyFactory = new PowerAuthServerKeyFactory();

        HashBasedCounter ctrGenerator = new HashBasedCounter("3.1");
        byte[] ctrData = ctrGenerator.init();

        for (int i = 0; i < 5; i++) {

            System.out.println();
            System.out.println("# PowerAuth Authentication Test - Round " + i);
            System.out.println("# 1FA ====");

            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data authentication code
                System.out.println("## Client Authentication Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey clientKeyPossession = clientKeyFactory.generateClientPossessionFactorKey(masterClientKey);
                System.out.println("### Client Possession Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientKeyPossession)));

                String authenticationCode = clientAuth.computeAuthCode(data, Collections.singletonList(clientKeyPossession), ctrData, authenticationCodeConfiguration);

                System.out.println("## Client Authentication Code: " + authenticationCode);

                // validate authentication code
                System.out.println("## Server Authentication Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey serverKeyPossession = serverKeyFactory.generateServerPossessionFactorKey(masterServerKey);
                System.out.println("### Server Possession Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverKeyPossession)));
                assertEquals(clientKeyPossession, serverKeyPossession);

                boolean isAuthenticationCodeValid = serverAuth.verifyAuthenticationForData(data, authenticationCode, Collections.singletonList(serverKeyPossession), ctrData, authenticationCodeConfiguration);
                System.out.println("## Authentication Code valid: " + (isAuthenticationCodeValid ? "TRUE" : "FALSE"));
                assertTrue(isAuthenticationCodeValid);

                ctrData = ctrGenerator.next(ctrData);
            }

            System.out.println("# 2FA ====");
            for (int j = 0; j < 20; j++) {

                System.out.println();
                System.out.println("## Counter: " + Base64.getEncoder().encodeToString(ctrData));

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));
                System.out.println("## Data: " + Base64.getEncoder().encodeToString(data));

                // compute data authentication code
                System.out.println("## Client Authentication Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey clientKeyPossession = clientKeyFactory.generateClientPossessionFactorKey(masterClientKey);
                System.out.println("### Client Key - Possession: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientKeyPossession)));
                SecretKey clientKeyKnowledge = clientKeyFactory.generateClientKnowledgeFactorKey(masterClientKey);
                System.out.println("### Client Key - Knowledge:  " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientKeyKnowledge)));

                String authenticationCode = clientAuth.computeAuthCode(data, Arrays.asList(clientKeyPossession, clientKeyKnowledge), ctrData, authenticationCodeConfiguration);

                System.out.println("## Client Authentication Code: " + authenticationCode);

                // validate authentication code
                System.out.println("## Server Authentication Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey serverKeyPossession = serverKeyFactory.generateServerPossessionFactorKey(masterServerKey);
                System.out.println("### Server Possession Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverKeyPossession)));
                assertEquals(clientKeyPossession, serverKeyPossession);
                SecretKey serverKeyKnowledge = serverKeyFactory.generateServerKnowledgeFactorKey(masterServerKey);
                System.out.println("### Server Knowledge Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverKeyKnowledge)));
                assertEquals(clientKeyKnowledge, serverKeyKnowledge);

                boolean isAuthenticationCodeValid = serverAuth.verifyAuthenticationForData(data, authenticationCode, Arrays.asList(serverKeyPossession, clientKeyKnowledge), ctrData, authenticationCodeConfiguration);
                System.out.println("## Authentication Code valid: " + (isAuthenticationCodeValid ? "TRUE" : "FALSE"));
                assertTrue(isAuthenticationCodeValid);

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
                authenticationCodeConfiguration.setLength(componentLength);

                // compute data authentication code
                System.out.println("## Client Authentication Key Derivation");
                SecretKey masterClientKey = clientKeyFactory.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                System.out.println("### Client Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterClientKey)));
                SecretKey clientKeyPossession = clientKeyFactory.generateClientPossessionFactorKey(masterClientKey);
                System.out.println("### Client Key - Possession: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientKeyPossession)));
                SecretKey clientKeyKnowledge = clientKeyFactory.generateClientKnowledgeFactorKey(masterClientKey);
                System.out.println("### Client Key - Knowledge:  " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientKeyKnowledge)));

                String authenticationCode = clientAuth.computeAuthCode(data, Arrays.asList(clientKeyPossession, clientKeyKnowledge), ctrData, authenticationCodeConfiguration);

                System.out.println("## Client Authentication Code: " + authenticationCode);
                assertEquals(componentLength * 2 + 1, authenticationCode.length());

                // validate authentication code
                System.out.println("## Server Authentication Key Derivation");

                SecretKey masterServerKey = serverKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                System.out.println("### Server Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(masterServerKey)));
                assertEquals(masterClientKey, masterServerKey);

                SecretKey serverKeyPossession = serverKeyFactory.generateServerPossessionFactorKey(masterServerKey);
                System.out.println("### Server Possession Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverKeyPossession)));
                assertEquals(clientKeyPossession, serverKeyPossession);
                SecretKey serverKeyKnowledge = serverKeyFactory.generateServerKnowledgeFactorKey(masterServerKey);
                System.out.println("### Server Knowledge Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(serverKeyKnowledge)));
                assertEquals(clientKeyKnowledge, serverKeyKnowledge);

                boolean isAuthenticationCodeValid = serverAuth.verifyAuthenticationForData(data, authenticationCode, Arrays.asList(serverKeyPossession, clientKeyKnowledge), ctrData, authenticationCodeConfiguration);
                System.out.println("## Authentication Code valid: " + (isAuthenticationCodeValid ? "TRUE" : "FALSE"));
                assertTrue(isAuthenticationCodeValid);

                ctrData = ctrGenerator.next(ctrData);
            }
        }
    }

}
