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

import com.google.common.io.BaseEncoding;
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
        System.out.println("Private Key: " + BaseEncoding.base64().encode(keyConvertor.convertPrivateKeyToBytes(kp.getPrivate())));
        System.out.println("Public Key: " + BaseEncoding.base64().encode(keyConvertor.convertPublicKeyToBytes(kp.getPublic())));
    }

    /**
     * Test of the complete activation process, orchestration between client and server.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @throws Exception In case test fails
     */
    @Test
    public void testActivationProcessV2() throws Exception {

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
            String activationId = serverActivation.generateActivationId();
            String activationCode = serverActivation.generateActivationCode();
            String activationIdShort = activationCode.substring(0, 11);
            String activationOtp = activationCode.substring(12);
            byte[] activationSignature = serverActivation.generateActivationSignature(activationCode, masterPrivateKey);
            KeyPair serverKeyPair = serverActivation.generateServerKeyPair();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            PublicKey serverPublicKey = serverKeyPair.getPublic();

            // CLIENT: Verify activation signature
            boolean activationSignatureOK = clientActivation.verifyActivationCodeSignature(activationCode, activationSignature, masterPublicKey);
            assertTrue(activationSignatureOK);

            // CLIENT: Generate and send public key
            KeyPair deviceKeyPair = clientActivation.generateDeviceKeyPair();
            KeyPair clientEphemeralKeyPair = keyGenerator.generateKeyPair();
            PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
            PublicKey devicePublicKey = deviceKeyPair.getPublic();
            byte[] clientNonce = clientActivation.generateActivationNonce();
            byte[] c_devicePublicKey = clientActivation.encryptDevicePublicKey(
                    devicePublicKey,
                    clientEphemeralKeyPair.getPrivate(),
                    masterPublicKey,
                    activationOtp,
                    activationIdShort,
                    clientNonce
            );

            // SERVER: Decrypt device public key
            PublicKey decryptedDevicePublicKey = serverActivation.decryptDevicePublicKey(
                    c_devicePublicKey,
                    activationIdShort,
                    masterPrivateKey,
                    clientEphemeralKeyPair.getPublic(),
                    activationOtp,
                    clientNonce
            );
            assertEquals(devicePublicKey, decryptedDevicePublicKey);

            // SERVER: Encrypt and send encrypted server public and it's signature
            KeyPair ephemeralKeyPair = keyGenerator.generateKeyPair();
            PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
            PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();
            byte[] serverNonce = serverActivation.generateActivationNonce();
            byte[] c_serverPublicKey = serverActivation.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOtp, activationIdShort, serverNonce);
            byte[] c_serverPublicKeySignature = serverActivation.computeServerDataSignature(activationId, c_serverPublicKey, masterPrivateKey);

            // CLIENT: Validate server public key signature and decrypt server public key
            boolean serverPublicKeySignatureOK = clientActivation.verifyServerDataSignature(activationId, c_serverPublicKey, c_serverPublicKeySignature, masterPublicKey);
            assertTrue(serverPublicKeySignatureOK);

            PublicKey decryptedServerPublicKey = clientActivation.decryptServerPublicKey(c_serverPublicKey, devicePrivateKey, ephemeralPublicKey, activationOtp, activationIdShort, serverNonce);
            assertEquals(serverPublicKey, decryptedServerPublicKey);

            // CLIENT and SERVER: Compute device public key fingerprint
            String devicePublicKeyFingerprintClient = clientActivation.computeActivationFingerprint(devicePublicKey);
            String devicePublicKeyFingerprintServer = serverActivation.computeActivationFingerprint(decryptedDevicePublicKey);
            assertEquals(devicePublicKeyFingerprintClient, devicePublicKeyFingerprintServer);

            // CLIENT and SERVER: Compute shared master secret
            SecretKey sharedMasterSecretDevice = keyGenerator.computeSharedKey(devicePrivateKey, serverPublicKey);
            SecretKey sharedMasterSecretServer = keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
            assertEquals(sharedMasterSecretDevice, sharedMasterSecretServer);

        }
    }

    /**
     * Test of the complete activation process, orchestration between client and server.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     * <li>3.0</li>
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
     * Test public key encryption.
     *
     * @throws Exception When test fails.
     */
    @Test
    public void testActivationGenerate() throws Exception {
        String activationOTP = "CKZ2O-OE544";
        String activationIdShort = "IFA6F-3NPAZ";
        byte[] activationNonce = BaseEncoding.base64().decode("grDwkvXrgfUdKBsqg0xYYw==");
        byte[] publicKeyBytes = BaseEncoding.base64().decode("BJXfJMCANX+T9FzsG6Hi0KTYPN64i7HxMiWoMYPd17DYfBR+IwzOesTh/jj/B3trL9m3O1oODYil+8ssJzDt/QA=");
        byte[] ephemeralPrivateKeyBytes = BaseEncoding.base64().decode("AKeMTtivK/XRiQPhfJYxAw1L62ah4lGTQ4JKqRrr0fnC");
        byte[] masterPublicKey = BaseEncoding.base64().decode("BFOqvpLNi15eHDt8fkFxFe034Buw/i8gR3ax4fKiIQynt5K858oBBYhqLVH8FhNmMnlysnRd2UsPJSQxzoPhEn8=");

        PrivateKey eph = keyConvertor.convertBytesToPrivateKey(ephemeralPrivateKeyBytes);
        PublicKey mpk = keyConvertor.convertBytesToPublicKey(masterPublicKey);

        PublicKey publicKey = keyConvertor.convertBytesToPublicKey(publicKeyBytes);
        PowerAuthClientActivation activation = new PowerAuthClientActivation();

        byte[] cDevicePublicKey = activation.encryptDevicePublicKey(publicKey, eph, mpk, activationOTP, activationIdShort, activationNonce);
        assertArrayEquals(cDevicePublicKey, BaseEncoding.base64().decode("tnAyB0C5I9xblLlFCPONUT4GtABvutPkRvvx2oTeGIuUMAmUYTqJluKn/Zge+vbq+VArIVNYVTd+0yuBZGVtkkd1mTcc2eTDhqZSQJS6mMgmKeCqv64c6E4dm4INOkxh"));
    }

    /**
     * Test that public key fingerprints are correctly computed.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     * <li>2.0</li>
     * <li>2.1</li>
     * </ul>
     *
     * @throws Exception When test fails.
     */
    @Test
    public void testPublicKeyFingerprintV2() throws Exception {

        String[] publicKeysBase64 = {
                "BLaTpcUMJU3BYuF8kgeQjYUZp3nHrepNzeOp68bJbdcUtayIWDhLVtX5qFkLoXXsMH6UnxEJXaMbGOCN3i8eDOI",
                "BFxZEGvqTOFolI6cvdJLiQZR3vSFfsajfJz6qHiOtDlKp5PcoMkUKlxC7hXUcRnZy9C8e6wHATahy2y5Y5OzOKc=",
                "BFUKKJvx/jhAuqvCHWet0mY42ACPT+eKL54kusaDgcoIgN9OcrFbPFS0wuTIMM65YAcUvkcmW9SjHs7QwKjMGQM="
        };
        String[] publicKeyFingerprint = {
                "85240323",
                "27352787",
                "52209841"
        };

        PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
        PowerAuthServerActivation serverActivation = new PowerAuthServerActivation();

        for (int i = 0; i < publicKeyFingerprint.length; i++) {
            byte[] publicKeyBytes = BaseEncoding.base64().decode(publicKeysBase64[i]);
            PublicKey publicKey = keyConvertor.convertBytesToPublicKey(publicKeyBytes);
            final String fingerprintClient = clientActivation.computeActivationFingerprint(publicKey);
            final String fingerprintServer = serverActivation.computeActivationFingerprint(publicKey);
            assertEquals(publicKeyFingerprint[i], fingerprintClient);
            assertEquals(publicKeyFingerprint[i], fingerprintServer);
        }
    }

    /**
     * Test that public key fingerprints are correctly computed.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     * <li>3.0</li>
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
            byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(devicePublicKeysBase64[i]);
            byte[] serverPublicKeyBytes = BaseEncoding.base64().decode(serverPublicKeysBase64[i]);
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
