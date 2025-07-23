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
package com.wultra.security.powerauth.crypto.vault;

import com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthDerivedKey;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.server.vault.PowerAuthServerVault;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test the secure vault implementation.
 *
 * @author Petr Dvorak
 */
public class VaultTest {

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
     * Test the secure vault implementation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
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
        KeyPair deviceKeyPair = keyGenerator.generateKeyPair(EcCurve.P256);
        KeyPair serverKeyPair = keyGenerator.generateKeyPair(EcCurve.P256);

        // Deduce shared master secret keys
        SecretKey deviceMasterKey = keyGenerator.computeSharedKey(deviceKeyPair.getPrivate(), serverKeyPair.getPublic());
        SecretKey serverMasterKey = keyGenerator.computeSharedKey(serverKeyPair.getPrivate(), deviceKeyPair.getPublic());
        assertEquals(deviceMasterKey, serverMasterKey);

        System.out.println("## Master Secret Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(deviceMasterKey)));

        // Deduce client vault encryption key and client / server master transport key
        SecretKey clientVaultEncryptionKey = keyFactory.generateServerEncryptedVaultKey(deviceMasterKey);
        System.out.println("## Vault Encryption Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientVaultEncryptionKey)));

        SecretKey clientTransportKey = keyGenerator.deriveSecretKey(deviceMasterKey, PowerAuthDerivedKey.TRANSPORT.getIndex());
        SecretKey serverTransportKey = keyGenerator.deriveSecretKey(serverMasterKey, PowerAuthDerivedKey.TRANSPORT.getIndex());
        assertEquals(clientTransportKey, serverTransportKey);
        System.out.println("## Master Transport Key: " + Base64.getEncoder().encodeToString(keyConvertor.convertSharedSecretKeyToBytes(clientTransportKey)));

        // Encrypt device private key
        byte[] cDevicePrivateKey = clientVault.encryptDevicePrivateKey(deviceKeyPair.getPrivate(), clientVaultEncryptionKey);

        // Get encrypted vault encryption key from the server
        byte[] cVaultEncryptionKey = serverVault.encryptVaultEncryptionKey(serverKeyPair.getPrivate(), deviceKeyPair.getPublic());
        System.out.println("## cVaultEncryptionKey: " + Base64.getEncoder().encodeToString(cVaultEncryptionKey));

        SecretKey vaultEncryptionKeyLocal = clientVault.decryptVaultEncryptionKey(cVaultEncryptionKey, clientTransportKey);
        assertEquals(clientVaultEncryptionKey, vaultEncryptionKeyLocal);

        PrivateKey devicePrivateKeyLocal = clientVault.decryptDevicePrivateKey(cDevicePrivateKey, vaultEncryptionKeyLocal);
        assertEquals(((BCECPrivateKey)deviceKeyPair.getPrivate()).getD(), ((BCECPrivateKey)devicePrivateKeyLocal).getD());

    }

}
