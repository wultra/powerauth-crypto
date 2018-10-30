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
package io.getlime.security.powerauth.crypto.vault;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthDerivedKey;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.server.vault.PowerAuthServerVault;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;

import static org.junit.Assert.assertEquals;

/**
 * Test the secure vault implementation.
 *
 * @author Petr Dvorak
 */
public class VaultTest {

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
     * Test the secure vault implementation.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @throws Exception In case the test fails.
     */
    @Test
    public void testVaultV2() throws Exception {

        System.out.println("# PowerAuth Secure Vault");
        System.out.println();

        PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();

        // Prepare test data
        KeyGenerator keyGenerator = new KeyGenerator();
        PowerAuthClientVault clientVault = new PowerAuthClientVault();
        PowerAuthServerVault serverVault = new PowerAuthServerVault();

        // Generate fake server and device keys
        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        KeyPair serverKeyPair = keyGenerator.generateKeyPair();

        // Deduce shared master secret keys
        SecretKey deviceMasterKey = keyGenerator.computeSharedKey(deviceKeyPair.getPrivate(), serverKeyPair.getPublic());
        SecretKey serverMasterKey = keyGenerator.computeSharedKey(serverKeyPair.getPrivate(), deviceKeyPair.getPublic());
        assertEquals(deviceMasterKey, serverMasterKey);

        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        System.out.println("## Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(deviceMasterKey)));

        // Deduce client vault encryption key and client / server master transport key
        SecretKey clientVaultEncryptionKey = keyFactory.generateServerEncryptedVaultKey(deviceMasterKey);
        System.out.println("## Vault Encryption Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(clientVaultEncryptionKey)));

        SecretKey clientTransportKey = keyGenerator.deriveSecretKey(deviceMasterKey, PowerAuthDerivedKey.TRANSPORT.getIndex());
        SecretKey serverTransportKey = keyGenerator.deriveSecretKey(serverMasterKey, PowerAuthDerivedKey.TRANSPORT.getIndex());
        assertEquals(clientTransportKey, serverTransportKey);
        System.out.println("## Master Transport Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(clientTransportKey)));

        // Encrypt device private key
        byte[] cDevicePrivateKey = clientVault.encryptDevicePrivateKey(deviceKeyPair.getPrivate(), clientVaultEncryptionKey);

        // Get encrypted vault encryption key from the server
        for (long ctr = 0; ctr < 50; ctr++) {

            System.out.println();
            System.out.println("## Counter: " + ctr);

            byte[] ctrBytes = ByteBuffer.allocate(16).putLong(0L).putLong(ctr).array();
            byte[] cVaultEncryptionKey = serverVault.encryptVaultEncryptionKey(serverKeyPair.getPrivate(), deviceKeyPair.getPublic(), ctrBytes);
            System.out.println("## cVaultEncryptionKey: " + BaseEncoding.base64().encode(cVaultEncryptionKey));

            SecretKey vaultEncryptionKeyLocal = clientVault.decryptVaultEncryptionKey(cVaultEncryptionKey, clientTransportKey, ctrBytes);
            assertEquals(clientVaultEncryptionKey, vaultEncryptionKeyLocal);

            PrivateKey devicePrivateKeyLocal = clientVault.decryptDevicePrivateKey(cDevicePrivateKey, vaultEncryptionKeyLocal);
            assertEquals(deviceKeyPair.getPrivate(), devicePrivateKeyLocal);
        }

    }

    /**
     * Test the secure vault implementation.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @throws Exception In case the test fails.
     */
    @Test
    public void testVaultV3() throws Exception {

        System.out.println("# PowerAuth Secure Vault");
        System.out.println();

        PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();

        // Prepare test data
        KeyGenerator keyGenerator = new KeyGenerator();
        PowerAuthClientVault clientVault = new PowerAuthClientVault();
        PowerAuthServerVault serverVault = new PowerAuthServerVault();

        // Generate fake server and device keys
        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        KeyPair serverKeyPair = keyGenerator.generateKeyPair();

        // Deduce shared master secret keys
        SecretKey deviceMasterKey = keyGenerator.computeSharedKey(deviceKeyPair.getPrivate(), serverKeyPair.getPublic());
        SecretKey serverMasterKey = keyGenerator.computeSharedKey(serverKeyPair.getPrivate(), deviceKeyPair.getPublic());
        assertEquals(deviceMasterKey, serverMasterKey);

        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        System.out.println("## Master Secret Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(deviceMasterKey)));

        // Deduce client vault encryption key and client / server master transport key
        SecretKey clientVaultEncryptionKey = keyFactory.generateServerEncryptedVaultKey(deviceMasterKey);
        System.out.println("## Vault Encryption Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(clientVaultEncryptionKey)));

        SecretKey clientTransportKey = keyGenerator.deriveSecretKey(deviceMasterKey, PowerAuthDerivedKey.TRANSPORT.getIndex());
        SecretKey serverTransportKey = keyGenerator.deriveSecretKey(serverMasterKey, PowerAuthDerivedKey.TRANSPORT.getIndex());
        assertEquals(clientTransportKey, serverTransportKey);
        System.out.println("## Master Transport Key: " + BaseEncoding.base64().encode(keyConvertor.convertSharedSecretKeyToBytes(clientTransportKey)));

        // Encrypt device private key
        byte[] cDevicePrivateKey = clientVault.encryptDevicePrivateKey(deviceKeyPair.getPrivate(), clientVaultEncryptionKey);

        // Get encrypted vault encryption key from the server
        byte[] cVaultEncryptionKey = serverVault.encryptVaultEncryptionKey(serverKeyPair.getPrivate(), deviceKeyPair.getPublic());
        System.out.println("## cVaultEncryptionKey: " + BaseEncoding.base64().encode(cVaultEncryptionKey));

        SecretKey vaultEncryptionKeyLocal = clientVault.decryptVaultEncryptionKey(cVaultEncryptionKey, clientTransportKey);
        assertEquals(clientVaultEncryptionKey, vaultEncryptionKeyLocal);

        PrivateKey devicePrivateKeyLocal = clientVault.decryptDevicePrivateKey(cDevicePrivateKey, vaultEncryptionKeyLocal);
        assertEquals(deviceKeyPair.getPrivate(), devicePrivateKeyLocal);

    }

}
