/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.crypto.client.vault;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class implementing client-side processes related to PowerAuth secure vault.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthClientVault {

    /**
     * Decrypts the vault encryption key KEY_ENCRYPTION_VAULT using a transport key
     * KEY_ENCRYPTION_VAULT_TRANSPORT.
     * @param cVaultEncryptionKey Encrypted vault encryption key KEY_ENCRYPTION_VAULT.
     * @param masterTransportKey Master transport key used for deriving a transport key, used for decrypting vault encryption key.
     * @param ctr Counter used for key derivation.
     * @return Original KEY_ENCRYPTION_VAULT
     * @throws InvalidKeyException In case invalid key is provided.
     */
    public SecretKey decryptVaultEncryptionKey(byte[] cVaultEncryptionKey, SecretKey masterTransportKey, long ctr) throws InvalidKeyException {
        AESEncryptionUtils aes = new AESEncryptionUtils();
        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
        KeyGenerator keyGen = new KeyGenerator();
        SecretKey vaultEncryptionTransportKey = keyGen.deriveSecretKey(masterTransportKey, ctr);
        byte[] zeroBytes = new byte[16];
        try {
            byte[] keyBytes = aes.decrypt(cVaultEncryptionKey, zeroBytes, vaultEncryptionTransportKey);
            return keyConvertor.convertBytesToSharedSecretKey(keyBytes);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(PowerAuthClientVault.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Encrypts original device private key KEY_DEVICE_PRIVATE using the vault
     * encryption key KEY_ENCRYPTION_VAULT.
     * @param devicePrivateKey Device private key KEY_DEVICE_PRIVATE.
     * @param vaultEncryptionKey Vault encryption key KEY_ENCRYPTION_VAULT.
     * @return Encrypted private key.
     * @throws InvalidKeyException In case invalid key is provided.
     */
    public byte[] encryptDevicePrivateKey(PrivateKey devicePrivateKey, SecretKey vaultEncryptionKey) throws InvalidKeyException {
        try {
            AESEncryptionUtils aes = new AESEncryptionUtils();
            CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
            byte[] devicePrivateKeyBytes = keyConvertor.convertPrivateKeyToBytes(devicePrivateKey);
            byte[] zeroBytes = new byte[16];
            return aes.encrypt(devicePrivateKeyBytes, zeroBytes, vaultEncryptionKey);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(PowerAuthClientVault.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Decrypts original device private key KEY_DEVICE_PRIVATE using the vault
     * encryption key KEY_ENCRYPTION_VAULT.
     * @param cDevicePrivateKey Encrypted device private key KEY_DEVICE_PRIVATE.
     * @param vaultEncryptionKey Vault encryption key KEY_ENCRYPTION_VAULT.
     * @return Original private key.
     * @throws InvalidKeyException In case invalid key is provided.
     */
    public PrivateKey decryptDevicePrivateKey(byte[] cDevicePrivateKey, SecretKey vaultEncryptionKey) throws InvalidKeyException {
        AESEncryptionUtils aes = new AESEncryptionUtils();
        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
        byte[] zeroBytes = new byte[16];
        try {
            byte[] keyBytes = aes.decrypt(cDevicePrivateKey, zeroBytes, vaultEncryptionKey);
            return keyConvertor.convertBytesToPrivateKey(keyBytes);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException ex) {
            Logger.getLogger(PowerAuthClientVault.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

}
