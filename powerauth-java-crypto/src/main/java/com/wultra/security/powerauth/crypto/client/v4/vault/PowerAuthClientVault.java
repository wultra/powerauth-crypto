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
package com.wultra.security.powerauth.crypto.client.v4.vault;

import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import com.wultra.security.powerauth.crypto.lib.util.ByteUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Client-side processes for PowerAuth secure vault (V4).
 * <p>
 * Algorithm: AES-256-CBC with PKCS7 padding.
 * Serialization: IV(16) || CIPHERTEXT
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@gmail.com
 */
public class PowerAuthClientVault {

    private static final int AES_IV_LENGTH = 16;
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS7Padding";

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC = new MlDsaKeyConvertor();
    private static final AESEncryptionUtils AES_UTILS = new AESEncryptionUtils();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    /**
     * Encrypt original EC device private key KEY_DEVICE_PRIVATE using the vault
     * encryption key KEK_DEVICE_PRIVATE (AES-256).
     *
     * @param devicePrivateKey Device private key (P-384).
     * @param vaultEncryptionKey Vault encryption key.
     * @return Encrypted device private key.
     * @throws InvalidKeyException In case key is invalid.
     * @throws GenericCryptoException In case key encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] encryptEcDevicePrivateKey(PrivateKey devicePrivateKey, SecretKey vaultEncryptionKey)
            throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        final byte[] privateKeyBytes = KEY_CONVERTOR_EC.convertPrivateKeyToBytes(devicePrivateKey);
        final byte[] iv = KEY_GENERATOR.generateRandomBytes(AES_IV_LENGTH);
        final byte[] ciphertext = AES_UTILS.encrypt(privateKeyBytes, iv, vaultEncryptionKey, AES_TRANSFORMATION);
        return ByteUtils.concat(iv, ciphertext);
    }

    /**
     * Encrypt original PQC device private key KEY_DEVICE_PRIVATE using the vault
     * encryption key KEK_DEVICE_PRIVATE (AES-256).
     *
     * @param devicePrivateKey Device private key (ML-DSA).
     * @param vaultEncryptionKey Vault encryption key.
     * @return Encrypted device private key.
     * @throws InvalidKeyException In case key is invalid.
     * @throws GenericCryptoException In case key encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] encryptPqcDevicePrivateKey(PrivateKey devicePrivateKey, SecretKey vaultEncryptionKey)
            throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        final byte[] privateKeyBytes = KEY_CONVERTOR_PQC.convertPrivateKeyToBytes(devicePrivateKey);
        final byte[] iv = KEY_GENERATOR.generateRandomBytes(AES_IV_LENGTH);
        final byte[] ciphertext = AES_UTILS.encrypt(privateKeyBytes, iv, vaultEncryptionKey, AES_TRANSFORMATION);
        return ByteUtils.concat(iv, ciphertext);
    }

    /**
     * Decrypt the original EC device private key KEY_DEVICE_PRIVATE using the vault
     * encryption key KEK_DEVICE_PRIVATE (AES-256).
     *
     * @param encryptedBytes Encrypted device private key (P-384).
     * @param vaultEncryptionKey Vault encryption key.
     * @return Decrypted device private key.
     * @throws InvalidKeyException In case key is invalid.
     * @throws InvalidKeySpecException In case key specification is invalid.
     * @throws GenericCryptoException In case key decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public PrivateKey decryptEcDevicePrivateKey(byte[] encryptedBytes, SecretKey vaultEncryptionKey)
            throws InvalidKeyException, InvalidKeySpecException, GenericCryptoException, CryptoProviderException {
        if (encryptedBytes == null || encryptedBytes.length < AES_IV_LENGTH) {
            throw new GenericCryptoException("Invalid ciphertext");
        }
        byte[] iv = ByteUtils.subarray(encryptedBytes, 0, AES_IV_LENGTH);
        byte[] ciphertext = ByteUtils.subarray(encryptedBytes, AES_IV_LENGTH, encryptedBytes.length - AES_IV_LENGTH);
        byte[] keyBytes = AES_UTILS.decrypt(ciphertext, iv, vaultEncryptionKey, AES_TRANSFORMATION);
        return KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, keyBytes);
    }

    /**
     * Decrypt the original PQC device private key KEY_DEVICE_PRIVATE using the vault
     * encryption key KEK_DEVICE_PRIVATE (AES-256).
     *
     * @param encryptedBytes Encrypted device private key (MLDSA).
     * @param vaultEncryptionKey Vault encryption key.
     * @return Decrypted device private key.
     * @throws InvalidKeyException In case key is invalid.
     * @throws GenericCryptoException In case key decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public PrivateKey decryptPqcDevicePrivateKey(byte[] encryptedBytes, SecretKey vaultEncryptionKey)
            throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        if (encryptedBytes == null || encryptedBytes.length < AES_IV_LENGTH) {
            throw new GenericCryptoException("Invalid ciphertext");
        }
        byte[] iv = ByteUtils.subarray(encryptedBytes, 0, AES_IV_LENGTH);
        byte[] ciphertext = ByteUtils.subarray(encryptedBytes, AES_IV_LENGTH, encryptedBytes.length - AES_IV_LENGTH);
        byte[] keyBytes = AES_UTILS.decrypt(ciphertext, iv, vaultEncryptionKey, AES_TRANSFORMATION);
        return KEY_CONVERTOR_PQC.convertBytesToPrivateKey(keyBytes);
    }

}
