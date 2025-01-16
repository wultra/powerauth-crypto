/*
 * PowerAuth Crypto Library
 * Copyright 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.crypto.lib.v4;

import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.crypto.lib.v4.kdf.Kdf;
import io.getlime.security.powerauth.crypto.lib.v4.kdf.Kmac;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * Implementation of authenticated encryption with associated data.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Aead {

    private static final int NONCE_LENGTH = 12;
    private static final int KEY_LENGTH = 32;
    private static final int TAG_LENGTH = 32;

    private static final byte[] CRYPTO4_AEAD_KMAC_CUSTOM_BYTES = "PA4MAC-AEAD".getBytes(StandardCharsets.UTF_8);
    private static final long KEY_ENCRYPTION_INDEX = 20_001L;
    private static final long KEY_MAC_INDEX = 20_002L;

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final AESEncryptionUtils aes = new AESEncryptionUtils();

    /**
     * Encrypt provided plaintext data using AEAD.
     *
     * @param key Secret key used for encryption.
     * @param keyContext Context data used during key derivation.
     * @param nonce A 12-byte array used as a unique nonce. If not specified, a random nonce is generated.
     * @param associatedData Additional data used as additional input for MAC derivation.
     * @param plaintext Plaintext data to encrypt.
     * @return Byte array with nonce, MAC, and encrypted ciphertext.
     * @throws CryptoProviderException Thrown in case the cryptographic provider could not be initialized.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     * @throws InvalidKeyException Thrown in case the secret key is invalid.
     */
    public static byte[] seal(SecretKey key, byte[] keyContext, byte[] nonce, byte[] associatedData, byte[] plaintext) throws CryptoProviderException, GenericCryptoException, InvalidKeyException {
        if (nonce == null) {
            nonce = KEY_GENERATOR.generateRandomBytes(NONCE_LENGTH);
        } else if (nonce.length != NONCE_LENGTH) {
            throw new GenericCryptoException("Invalid nonce length: " + nonce.length);
        }
        final SecretKey keyEncryption = Kdf.derive(key, KEY_ENCRYPTION_INDEX, KEY_LENGTH, keyContext);
        final SecretKey keyMac = Kdf.derive(key, KEY_MAC_INDEX, TAG_LENGTH, keyContext);
        final byte[] iv = ByteUtils.concat(nonce, ByteUtils.zeroBytes(4));
        final byte[] encrypted = aes.encrypt(plaintext, iv, keyEncryption, "AES/CTR/NoPadding");
        final byte[] mac = Kmac.kmac256(keyMac, ByteUtils.concat(nonce, associatedData, encrypted), TAG_LENGTH, CRYPTO4_AEAD_KMAC_CUSTOM_BYTES);
        return ByteUtils.concat(nonce, mac, encrypted);
    }

    /**
     * Decrypt provided ciphertext data using AEAD.
     *
     * @param key Secret key used for decryption.
     * @param keyContext Context data used during key derivation.
     * @param associatedData AAdditional data used as additional input for MAC derivation.
     * @param ciphertext Byte array with nonce, MAC, and encrypted ciphertext.
     * @return Byte array with decrypted data.
     * @throws CryptoProviderException Thrown in case the cryptographic provider could not be initialized.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     * @throws InvalidKeyException Thrown in case the secret key is invalid.
     */
    public static byte[] open(SecretKey key, byte[] keyContext, byte[] associatedData, byte[] ciphertext) throws CryptoProviderException, GenericCryptoException, InvalidKeyException {
        if (ciphertext.length < NONCE_LENGTH + TAG_LENGTH) {
            throw new GenericCryptoException("Invalid ciphertext length: " + ciphertext.length);
        }
        final byte[] nonce = ByteUtils.subarray(ciphertext, 0, NONCE_LENGTH);
        final byte[] tag = ByteUtils.subarray(ciphertext, NONCE_LENGTH, TAG_LENGTH);
        final byte[] encrypted = ByteUtils.subarray(ciphertext, NONCE_LENGTH + TAG_LENGTH, ciphertext.length - NONCE_LENGTH - TAG_LENGTH);
        final SecretKey keyEncryption = Kdf.derive(key, KEY_ENCRYPTION_INDEX, KEY_LENGTH, keyContext);
        final SecretKey keyMac = Kdf.derive(key, KEY_MAC_INDEX, TAG_LENGTH, keyContext);
        byte[] mac = Kmac.kmac256(keyMac, ByteUtils.concat(nonce, associatedData, encrypted), TAG_LENGTH, CRYPTO4_AEAD_KMAC_CUSTOM_BYTES);
        if (!Arrays.equals(mac, tag)) {
            throw new GenericCryptoException("Invalid MAC");
        }
        byte[] iv = ByteUtils.concat(nonce, ByteUtils.zeroBytes(4));
        return aes.decrypt(encrypted, iv, keyEncryption, "AES/CTR/NoPadding");
    }

    /**
     * Extract the nonce from provided ciphertext.
     *
     * @param ciphertext Byte array containing the nonce, MAC, and encrypted ciphertext.
     * @return Byte array with extracted nonce.
     * @throws GenericCryptoException Thrown in case the input ciphertext in invalid.
     */
    public static byte[] extractNonce(byte[] ciphertext) throws GenericCryptoException {
        if (ciphertext.length < NONCE_LENGTH + TAG_LENGTH) {
            throw new GenericCryptoException("Invalid ciphertext length: " + ciphertext.length);
        }
        return ByteUtils.subarray(ciphertext, 0, NONCE_LENGTH);
    }

}
