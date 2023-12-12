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
package io.getlime.security.powerauth.crypto.client.vault;

import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Class implementing client-side processes related to PowerAuth secure vault.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthClientVault {

    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Decrypts the vault encryption key KEY_ENCRYPTION_VAULT using KEY_TRANSPORT.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     * </ul>
     *
     * @param cVaultEncryptionKey Encrypted vault encryption key KEY_ENCRYPTION_VAULT.
     * @param transportKey Transport key used for for decrypting vault encryption key.
     * @return Original KEY_ENCRYPTION_VAULT
     * @throws InvalidKeyException In case invalid key is provided.
     * @throws GenericCryptoException In case decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey decryptVaultEncryptionKey(byte[] cVaultEncryptionKey, SecretKey transportKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] zeroBytes = new byte[16];
        byte[] keyBytes = aes.decrypt(cVaultEncryptionKey, zeroBytes, transportKey);
        return keyConvertor.convertBytesToSharedSecretKey(keyBytes);
    }

    /**
     * Encrypts original device private key KEY_DEVICE_PRIVATE using the vault
     * encryption key KEY_ENCRYPTION_VAULT.
     * @param devicePrivateKey Device private key KEY_DEVICE_PRIVATE.
     * @param vaultEncryptionKey Vault encryption key KEY_ENCRYPTION_VAULT.
     * @return Encrypted private key.
     * @throws InvalidKeyException In case invalid key is provided.
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] encryptDevicePrivateKey(PrivateKey devicePrivateKey, SecretKey vaultEncryptionKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] devicePrivateKeyBytes = keyConvertor.convertPrivateKeyToBytes(devicePrivateKey);
        byte[] zeroBytes = new byte[16];
        return aes.encrypt(devicePrivateKeyBytes, zeroBytes, vaultEncryptionKey);
    }

    /**
     * Decrypts original device private key KEY_DEVICE_PRIVATE using the vault
     * encryption key KEY_ENCRYPTION_VAULT.
     * @param cDevicePrivateKey Encrypted device private key KEY_DEVICE_PRIVATE.
     * @param vaultEncryptionKey Vault encryption key KEY_ENCRYPTION_VAULT.
     * @return Original private key.
     * @throws InvalidKeyException In case invalid key is provided.
     * @throws InvalidKeySpecException In case key spec is invalid.
     * @throws GenericCryptoException In case decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public PrivateKey decryptDevicePrivateKey(byte[] cDevicePrivateKey, SecretKey vaultEncryptionKey) throws InvalidKeyException, InvalidKeySpecException, GenericCryptoException, CryptoProviderException {
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] zeroBytes = new byte[16];
        byte[] keyBytes = aes.decrypt(cDevicePrivateKey, zeroBytes, vaultEncryptionKey);
        return keyConvertor.convertBytesToPrivateKey(keyBytes);
    }

}
