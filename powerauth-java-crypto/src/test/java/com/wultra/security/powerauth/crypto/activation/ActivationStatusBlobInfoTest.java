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
package com.wultra.security.powerauth.crypto.activation;

import com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyDerivationUtils;
import com.wultra.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import com.wultra.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test activation status blob.
 */
public class ActivationStatusBlobInfoTest {

    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    /**
     * Add crypto providers.
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testActivationStatusBlobZeroIV() throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        final PowerAuthServerActivation serverActivation = new PowerAuthServerActivation();
        final PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
        // Simulate generating of device and server key pairs
        final KeyPair keyPairDevice = KEY_GENERATOR.generateKeyPair(EcCurve.P256);
        final KeyPair keyPairServer = KEY_GENERATOR.generateKeyPair(EcCurve.P256);
        // Compute shared master secret key
        final SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(keyPairServer.getPrivate(), keyPairDevice.getPublic());
        // Derive transport key
        final SecretKey transportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterSecretKey);
        // Encrypt status blob with transport key
        ActivationStatusBlobInfo serverStatusBlob = new ActivationStatusBlobInfo();
        serverStatusBlob.setActivationStatus((byte)3);
        serverStatusBlob.setCurrentVersion((byte)2);
        serverStatusBlob.setUpgradeVersion((byte)3);
        serverStatusBlob.setFailedAttempts((byte)1);
        serverStatusBlob.setMaxFailedAttempts((byte)5);
        serverStatusBlob.setCtrLookAhead((byte)20);
        byte[] encryptedStatusBlob = serverActivation.encryptedStatusBlob(serverStatusBlob, null, null, transportKey, ProtocolVersion.V30);
        // Decrypt status blob with transport key
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] zeroIv = new KeyDerivationUtils().deriveIvForStatusBlobEncryption(null, null, transportKey);
        byte[] statusBlob = aes.decrypt(encryptedStatusBlob, zeroIv, transportKey, "AES/CBC/NoPadding");
        ByteBuffer buffer = ByteBuffer.wrap(statusBlob);
        // Status blob bytes 0 ... 6 are deterministic, verify them
        assertEquals(ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE_V3, buffer.getInt(0));
        assertEquals((byte) 3, buffer.get(4));
        assertEquals((byte) 2, buffer.get(5));
        assertEquals((byte) 3, buffer.get(6));
        // Status blob bytes 13 ... 14 contain version, verify them
        assertEquals((byte) 1, buffer.get(13));
        assertEquals((byte) 5, buffer.get(14));

        // Verify decoded status blob used in client activation
        final ActivationStatusBlobInfo statusBlobDecoded = clientActivation.getStatusFromEncryptedBlob(encryptedStatusBlob, null, null, transportKey);
        assertEquals(3, statusBlobDecoded.getActivationStatus());
        assertEquals(2, statusBlobDecoded.getCurrentVersion());
        assertEquals(3, statusBlobDecoded.getUpgradeVersion());
        assertEquals(1, statusBlobDecoded.getFailedAttempts());
        assertEquals(5, statusBlobDecoded.getMaxFailedAttempts());
        assertTrue(statusBlobDecoded.isValid());
    }

    @Test
    public void testActivationStatusBlobIV() throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        final PowerAuthServerActivation serverActivation = new PowerAuthServerActivation();
        final PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
        // Simulate generating of device and server key pairs
        final KeyPair keyPairDevice = KEY_GENERATOR.generateKeyPair(EcCurve.P256);
        final KeyPair keyPairServer = KEY_GENERATOR.generateKeyPair(EcCurve.P256);
        final byte[] challenge = KEY_GENERATOR.generateRandomBytes(16);
        final byte[] nonce = KEY_GENERATOR.generateRandomBytes(16);
        // Compute shared master secret key
        final SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(keyPairServer.getPrivate(), keyPairDevice.getPublic());
        // Derive transport key
        final SecretKey transportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterSecretKey);
        // Generate hash based counter
        byte[] ctrDataHash = KEY_GENERATOR.generateRandomBytes(16);
        // Encrypt status blob with transport key
        ActivationStatusBlobInfo serverStatusBlob = new ActivationStatusBlobInfo();
        serverStatusBlob.setActivationStatus((byte)3);
        serverStatusBlob.setCurrentVersion((byte)2);
        serverStatusBlob.setUpgradeVersion((byte)3);
        serverStatusBlob.setFailedAttempts((byte)1);
        serverStatusBlob.setMaxFailedAttempts((byte)5);
        serverStatusBlob.setCtrLookAhead((byte)20);
        serverStatusBlob.setCtrByte((byte)33);
        serverStatusBlob.setCtrDataHash(ctrDataHash);
        byte[] encryptedStatusBlob = serverActivation.encryptedStatusBlob(serverStatusBlob, challenge, nonce, transportKey, ProtocolVersion.V33);
        // Decrypt status blob with transport key
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] zeroIv = new KeyDerivationUtils().deriveIvForStatusBlobEncryption(challenge, nonce, transportKey);
        byte[] statusBlob = aes.decrypt(encryptedStatusBlob, zeroIv, transportKey, "AES/CBC/NoPadding");
        ByteBuffer buffer = ByteBuffer.wrap(statusBlob);
        // Status blob bytes 0 ... 6 are deterministic, verify them
        assertEquals(ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE_V3, buffer.getInt(0));
        assertEquals((byte) 3, buffer.get(4));
        assertEquals((byte) 2, buffer.get(5));
        assertEquals((byte) 3, buffer.get(6));
        // ctr byte is at position 12
        assertEquals((byte) 33, buffer.get(12));
        // Status blob bytes 13 ... 14 contain version, verify them
        assertEquals((byte) 1, buffer.get(13));
        assertEquals((byte) 5, buffer.get(14));
        // Look ahead window
        assertEquals((byte) 20, buffer.get(15));
        // Status blob bytes 16 ... 31 contain ctrData, verify them
        byte[] ctrDataFromStatus = Arrays.copyOfRange(statusBlob, 16, 32);
        assertArrayEquals(ctrDataHash, ctrDataFromStatus);

        // Verify decoded status blob used in client activation
        final ActivationStatusBlobInfo statusBlobDecoded = clientActivation.getStatusFromEncryptedBlob(encryptedStatusBlob, challenge, nonce, transportKey);
        assertEquals(3, statusBlobDecoded.getActivationStatus());
        assertEquals(2, statusBlobDecoded.getCurrentVersion());
        assertEquals(3, statusBlobDecoded.getUpgradeVersion());
        assertEquals(1, statusBlobDecoded.getFailedAttempts());
        assertEquals(5, statusBlobDecoded.getMaxFailedAttempts());
        assertEquals(20, statusBlobDecoded.getCtrLookAhead());
        assertEquals(33, statusBlobDecoded.getCtrByte());
        assertArrayEquals(ctrDataHash, statusBlobDecoded.getCtrDataHash());
        assertTrue(statusBlobDecoded.isValid());
    }

    @Test
    public void testActivationStatusBlobV4() throws GenericCryptoException, CryptoProviderException {
        final PowerAuthServerActivation serverActivation = new PowerAuthServerActivation();
        final PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();
        // Generate hash based counter
        byte[] ctrDataHash = KEY_GENERATOR.generateRandomBytes(16);
        ActivationStatusBlobInfo serverStatusBlob = new ActivationStatusBlobInfo();
        serverStatusBlob.setActivationStatus((byte)3);
        serverStatusBlob.setCurrentVersion((byte)3);
        serverStatusBlob.setUpgradeVersion((byte)4);
        serverStatusBlob.setFailedAttempts((byte)1);
        serverStatusBlob.setMaxFailedAttempts((byte)5);
        serverStatusBlob.setCtrLookAhead((byte)20);
        serverStatusBlob.setCtrByte((byte)33);
        serverStatusBlob.setCtrDataHash(ctrDataHash);
        serverStatusBlob.setStatusFlags((byte)1);
        byte[] statusBlob = serverActivation.generateStatusBlob(serverStatusBlob, ProtocolVersion.V40);
        // Decrypt status blob with transport key
        ByteBuffer buffer = ByteBuffer.wrap(statusBlob);
        // Status blob bytes 0 ... 7 are deterministic, verify them
        assertEquals(ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE_V4, buffer.getInt(0));
        assertEquals((byte) 3, buffer.get(4));
        assertEquals((byte) 3, buffer.get(5));
        assertEquals((byte) 4, buffer.get(6));
        assertEquals((byte) 1, buffer.get(7));
        // ctr byte is at position 12
        assertEquals((byte) 33, buffer.get(12));
        // Status blob bytes 13 ... 14 contain version, verify them
        assertEquals((byte) 1, buffer.get(13));
        assertEquals((byte) 5, buffer.get(14));
        // Look ahead window
        assertEquals((byte) 20, buffer.get(15));
        // Status blob bytes 16 ... 31 contain ctrData, verify them
        byte[] ctrDataFromStatus = Arrays.copyOfRange(statusBlob, 16, 32);
        assertArrayEquals(ctrDataHash, ctrDataFromStatus);

        // Verify decoded status blob used in client activation
        final ActivationStatusBlobInfo statusBlobDecoded = clientActivation.getStatusFromBlob(statusBlob);
        assertEquals(3, statusBlobDecoded.getActivationStatus());
        assertEquals(3, statusBlobDecoded.getCurrentVersion());
        assertEquals(4, statusBlobDecoded.getUpgradeVersion());
        assertEquals(1, statusBlobDecoded.getFailedAttempts());
        assertEquals(5, statusBlobDecoded.getMaxFailedAttempts());
        assertEquals(20, statusBlobDecoded.getCtrLookAhead());
        assertEquals(33, statusBlobDecoded.getCtrByte());
        assertArrayEquals(ctrDataHash, statusBlobDecoded.getCtrDataHash());
        assertTrue(statusBlobDecoded.isValid());
    }

}
