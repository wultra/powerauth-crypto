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
package io.getlime.security.powerauth.crypto.lib.util;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * A utility class for AES encryption.
 *
 * @author Petr Dvorak
 *
 */
public class AESEncryptionUtils {

    private static final Logger logger = LoggerFactory.getLogger(AESEncryptionUtils.class);

    /**
     * Encrypt given data using given transformation with given initialization
     * vector and secret key.
     *
     * @param bytes Bytes to be encrypted.
     * @param iv Initialization vector.
     * @param secret Secret signature key.
     * @param transformation Cipher transformation to be used, for example "AES/CBC/PKCS7Padding".
     * @return Encrypted bytes.
     * @throws InvalidKeyException In case an invalid key is provided.
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] encrypt(byte[] bytes, byte[] iv, SecretKey secret, String transformation) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        try {
            Cipher cipherForCryptoResponse = Cipher.getInstance(transformation, PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            cipherForCryptoResponse.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));
            return cipherForCryptoResponse.doFinal(bytes);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Encrypt given data using AES/CBC/PKCS7Padding with given initialization
     * vector and secret key.
     *
     * @param bytes Bytes to be encrypted.
     * @param iv Initialization vector.
     * @param secret Secret signature key.
     * @return Encrypted bytes.
     * @throws InvalidKeyException In case an invalid key is provided.
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] encrypt(byte[] bytes, byte[] iv, SecretKey secret) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return this.encrypt(bytes, iv, secret, "AES/CBC/PKCS7Padding");
    }

    /**
     * Decrypt given data using given transformation with given initialization
     * vector and secret key.
     *
     * @param bytes Encrypted bytes to be decrypted.
     * @param iv Initialization vector.
     * @param secret Secret signature key.
     * @param transformation Cipher transformation to be used, for example "AES/CBC/PKCS7Padding".
     * @return Original decrypted bytes.
     * @throws InvalidKeyException In case an invalid key is provided.
     * @throws GenericCryptoException In case decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] decrypt(byte[] bytes, byte[] iv, SecretKey secret, String transformation) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        try {
            Cipher cipherForCryptoResponse = Cipher.getInstance(transformation, PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            cipherForCryptoResponse.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
            return cipherForCryptoResponse.doFinal(bytes);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Decrypt given data using AES/CBC/PKCS7Padding with given initialization
     * vector and secret key.
     *
     * @param bytes Encrypted bytes to be decrypted.
     * @param iv Initialization vector.
     * @param secret Secret signature key.
     * @return Original decrypted bytes.
     * @throws InvalidKeyException In case an invalid key is provided.
     * @throws GenericCryptoException In case decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] decrypt(byte[] bytes, byte[] iv, SecretKey secret) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return this.decrypt(bytes, iv, secret, "AES/CBC/PKCS7Padding");
    }

}
