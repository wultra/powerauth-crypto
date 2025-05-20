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
package io.getlime.security.powerauth.crypto.activation;

import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author petrdvorak
 */
public class PowerAuthActivationTest {

    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Add crypto providers.
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test that the keys are correctly generated.
     */
    @Test
    public void testGenerateKeys() throws CryptoProviderException {
        KeyGenerator keyGenerator = new KeyGenerator();
        KeyPair kp = keyGenerator.generateKeyPair();
        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPrivateKeyToBytes(kp.getPrivate())));
        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(kp.getPublic())));
    }

    /**
     * Test of the complete activation process, orchestration between client and server.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *    <li>3.0</li>
     *    <li>3.1</li>
     *    <li>3.2</li>
     * </ul>
     *
     * @throws Exception In case test fails
     */
    @Test
    public void testActivationProcessV3() throws Exception {

        System.out.println("TEST: Activation Process");

        // Prepare test data
        KeyGenerator keyGenerator = new KeyGenerator();
        PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
        PowerAuthServerActivation serverActivation = new PowerAuthServerActivation();
        KeyPair masterKeyPair = keyGenerator.generateKeyPair();

        // Generate master keypair
        PrivateKey masterPrivateKey = masterKeyPair.getPrivate();
        PublicKey masterPublicKey = masterKeyPair.getPublic();

        for (int i = 0; i < 20; i++) {

            // SERVER: Generate data for activation
            String activationId = new IdentifierGenerator().generateActivationId();
            String activationCode = serverActivation.generateActivationCode();
            byte[] activationSignature = serverActivation.generateActivationSignature(activationCode, masterPrivateKey);
            KeyPair serverKeyPair = serverActivation.generateServerKeyPair();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            // CLIENT: Verify activation signature
            boolean activationSignatureOK = clientActivation.verifyActivationCodeSignature(activationCode, activationSignature, masterPublicKey);
            assertTrue(activationSignatureOK);

            // CLIENT: Generate key pair
            KeyPair deviceKeyPair = clientActivation.generateDeviceKeyPair();
            PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
            PublicKey devicePublicKey = deviceKeyPair.getPublic();

            // Public keys are exchanged using ECIES which guarantees delivery of same values

            // CLIENT and SERVER: Compute activation fingerprint
            String devicePublicKeyFingerprintClient = clientActivation.computeActivationFingerprint(devicePublicKey, serverPublicKey, activationId);
            String devicePublicKeyFingerprintServer = serverActivation.computeActivationFingerprint(devicePublicKey, serverPublicKey, activationId);
            assertEquals(devicePublicKeyFingerprintClient, devicePublicKeyFingerprintServer);

            // CLIENT and SERVER: Compute shared master secret
            SecretKey sharedMasterSecretDevice = keyGenerator.computeSharedKey(devicePrivateKey, serverPublicKey);
            SecretKey sharedMasterSecretServer = keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
            assertEquals(sharedMasterSecretDevice, sharedMasterSecretServer);
        }
    }

    /**
     * Test that public key fingerprints are correctly computed.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *    <li>3.0</li>
     *    <li>3.1</li>
     *    <li>3.2</li>
     * </ul>
     *
     * @throws Exception When test fails.
     */
    @Test
    public void testPublicKeyFingerprintV3() throws Exception {

        String[] devicePublicKeysBase64 = {
                "BHS5kLb7nQkN4D8hMNbYs7uAj1yVHShh5l/YKIZowo8cN4CK6Q/9X5jb0mQruk/RB4AenmNB9jSKv00T9J8EneA=",
                "BNkeX5+Uhnpqth/CeyUPkVY5ZKAhH5nmXVyutFz2r+PwRJOq9WncHRzu4HB4zzFD/qyF1r582WwY2leNJFryNvM=",
                "BPDPY3g+kQSkTu915tVjxhGAhtPH9ylWieXmqrS/cNHlC3/BNx3fWztUmLjDEToacSn0zMe997nwsNGV4ZYKemM="
        };
        String[] serverPublicKeysBase64 = {
                "BLVfJ2NrOBByBZhfS4UtEQU3fLhnzYbWdp3ZVEQPfKtTGXzXIpKqxCVwpRl3X++4OJQJoemybZ/cmkLU5fY2SZE=",
                "BHeql+2IAKdUV9PEfiYF6ydfi4sbNaSiX9pZerDl1X7Ow9eCEFXFM1jV+Pp8FenON4/QIr2kKqYw0h5tGDFo0Oc=",
                "BKoVSkmONQ0BCF+C9VxZZnB8O8acL4rwQY/GaT+Xl/BctT1zqoVcvq3LjsjK/ID/ec8ksLD/FIKNBK6UtA7/trY="
        };
        String[] activationId = {
                "6ae8cd16-67a7-4840-8d37-33d9aab6ea51",
                "95ff8d92-9511-4a2b-b531-de03b7b942cf",
                "615c9552-6e89-49ca-bc37-9108dc8553d8"
        };
        String[] publicKeyFingerprint = {
                "80201993",
                "26445499",
                "07506106"
        };

        PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
        PowerAuthServerActivation serverActivation = new PowerAuthServerActivation();

        for (int i = 0; i < publicKeyFingerprint.length; i++) {
            byte[] devicePublicKeyBytes = Base64.getDecoder().decode(devicePublicKeysBase64[i]);
            byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverPublicKeysBase64[i]);
            String activation1 = activationId[i];
            PublicKey devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
            PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
            final String fingerprintClient = clientActivation.computeActivationFingerprint(devicePublicKey, serverPublicKey, activation1);
            final String fingerprintServer = serverActivation.computeActivationFingerprint(devicePublicKey, serverPublicKey, activation1);
            assertEquals(publicKeyFingerprint[i], fingerprintClient);
            assertEquals(publicKeyFingerprint[i], fingerprintServer);
        }
    }

}
