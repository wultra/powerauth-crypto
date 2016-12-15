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
package io.getlime.security.powerauth.lib.util;

import io.getlime.security.powerauth.lib.config.PowerAuthConfiguration;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A utility class for AES encryption.
 *
 * @author Petr Dvorak
 *
 */
public class AESEncryptionUtils {

    /**
     * Encrypt given data using given padding with given initialization
     * vector and secret key.
     *
     * @param bytes Bytes to be encrypted.
     * @param iv Initialization vector.
     * @param secret Secret signature key.
     * @param padding Padding to be used, for example "AES/CBC/PKCS7Padding".
     * @return Encrypted bytes.
     * @throws InvalidKeyException In case an invalid key is provided.
     * @throws IllegalBlockSizeException In case invalid key size is provided.
     * @throws BadPaddingException In case invalid padding is provided. 
     */
    public byte[] encrypt(byte[] bytes, byte[] iv, SecretKey secret, String padding) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            Cipher cipherForCryptoResponse = Cipher.getInstance(padding, PowerAuthConfiguration.INSTANCE.getKeyConvertor().getProviderName());
            cipherForCryptoResponse.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));
            byte[] cryptoResponseData = cipherForCryptoResponse.doFinal(bytes);
            return cryptoResponseData;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(AESEncryptionUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
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
     * @throws IllegalBlockSizeException In case invalid key size is provided.
     * @throws BadPaddingException In case invalid padding is provided.
     */
    public byte[] encrypt(byte[] bytes, byte[] iv, SecretKey secret) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return this.encrypt(bytes, iv, secret, "AES/CBC/PKCS7Padding");
    }

    /**
     * Decrypt given data using give padding with given initialization
     * vector and secret key.
     *
     * @param bytes Encrypted bytes to be decrypted.
     * @param iv Initialization vector.
     * @param secret Secret signature key.
     * @param padding Padding to be used, for example "AES/CBC/PKCS7Padding".
     * @return Original decrypted bytes.
     * @throws InvalidKeyException In case an invalid key is provided.
     * @throws IllegalBlockSizeException In case invalid key size is provided.
     * @throws BadPaddingException In case invalid padding is provided.
     */
    public byte[] decrypt(byte[] bytes, byte[] iv, SecretKey secret, String padding) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            Cipher cipherForCryptoResponse = Cipher.getInstance(padding, PowerAuthConfiguration.INSTANCE.getKeyConvertor().getProviderName());
            cipherForCryptoResponse.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
            byte[] cryptoResponseData = cipherForCryptoResponse.doFinal(bytes);
            return cryptoResponseData;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(AESEncryptionUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
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
     * @throws IllegalBlockSizeException In case invalid key size is provided.
     * @throws BadPaddingException In case invalid padding is provided.
     */
    public byte[] decrypt(byte[] bytes, byte[] iv, SecretKey secret) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return this.decrypt(bytes, iv, secret, "AES/CBC/PKCS7Padding");
    }

}
