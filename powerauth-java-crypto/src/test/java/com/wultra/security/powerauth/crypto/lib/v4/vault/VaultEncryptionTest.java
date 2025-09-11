/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.crypto.lib.v4.vault;

import com.wultra.security.powerauth.crypto.client.v4.vault.PowerAuthClientVault;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsa;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test the encryption of secure vault private keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class VaultEncryptionTest {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final MlDsa ML_DSA = new MlDsa();

    /**
     * Register crypto providers.
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test the secure vault implementation for EC.
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @throws Exception In case the test fails.
     */
    @Test
    public void testVaultEc() throws Exception {
        System.out.println("# PowerAuth EC Device Private Key Encryption Test");
        System.out.println();

        // Prepare test data
        PowerAuthClientVault clientVault = new PowerAuthClientVault();

        // Generate fake server and device keys
        KeyPair deviceKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P384);

        SecretKey vaultEncryptionKey = KEY_GENERATOR.generateRandomSecretKey(32);

        // Encrypt device private key
        byte[] devicePrivateKeyEncrypted = clientVault.encryptEcDevicePrivateKey(deviceKeyPair.getPrivate(), vaultEncryptionKey);

        // Check decrypted device private key
        PrivateKey devicePrivateKeyDecrypted = clientVault.decryptEcDevicePrivateKey(devicePrivateKeyEncrypted, vaultEncryptionKey);
        assertEquals(deviceKeyPair.getPrivate(), devicePrivateKeyDecrypted);
    }

    /**
     * Test the secure vault implementation for PQC.
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @throws Exception In case the test fails.
     */
    @Test
    public void testVaultPqc() throws Exception {
        System.out.println("# PowerAuth PQC Device Private Key Encryption Test");
        System.out.println();

        // Prepare test data
        PowerAuthClientVault clientVault = new PowerAuthClientVault();

        // Generate fake server and device keys
        KeyPair deviceKeyPair = ML_DSA.generateKeyPair();

        SecretKey vaultEncryptionKey = KEY_GENERATOR.generateRandomSecretKey(32);

        // Encrypt device private key
        byte[] devicePrivateKeyEncrypted = clientVault.encryptPqcDevicePrivateKey(deviceKeyPair.getPrivate(), vaultEncryptionKey);

        // Check decrypted device private key
        PrivateKey devicePrivateKeyDecrypted = clientVault.decryptPqcDevicePrivateKey(devicePrivateKeyEncrypted, vaultEncryptionKey);
        assertEquals(deviceKeyPair.getPrivate(), devicePrivateKeyDecrypted);
    }

}
