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

package io.getlime.security.powerauth.crypto.lib.v4.kdf;

import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Universal KDF based on KMAC-256 (Keccak).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Kdf {

    private static final byte[] CRYPTO4_KDF_CUSTOM_BYTES = "PA4KDF".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CRYPTO4_PBKDF_CUSTOM_BYTES = "PA4PBKDF".getBytes(StandardCharsets.UTF_8);

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Derive a secret key based on an input key, numeric key index, requested key size and optional context.
     *
     * @param key Secret key to be used for key derivation.
     * @param index Key index (numeric).
     * @param outLength Requested derived key size.
     * @param context Optional context to use during key derivation.
     * @return Derived secret key.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public static SecretKey derive(SecretKey key, long index, int outLength, byte[] context) throws GenericCryptoException {
        if (key == null) {
            throw new GenericCryptoException("Missing secret key for key derivation");
        }
        if (index < 0L) {
            throw new GenericCryptoException("Invalid index used for key derivation");
        }
        final byte[] indexBytes = ByteUtils.encodeLong(index);
        final byte[] data;
        if (context != null) {
            data = ByteUtils.concat(indexBytes, ByteUtils.concatWithSizes(context));
        } else {
            data = indexBytes;
        }
        final byte[] output = Kmac.kmac256(key, data, outLength, CRYPTO4_KDF_CUSTOM_BYTES);
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(output);
    }

    /**
     * Derive a key using password-based key derivation.
     *
     * @param password Password used for the key derivation.
     * @param salt Salt used for the key derivation.
     * @param outLength Requested output length.
     * @return Derived secret key.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public static SecretKey derivePassword(String password, byte[] salt, int outLength) throws GenericCryptoException {
        if (password == null || password.isEmpty()) {
            throw new GenericCryptoException("Missing password for key derivation");
        }
        if (salt == null) {
            throw new GenericCryptoException("Missing salt for key derivation");
        }
        if (salt.length < 32) {
            throw new GenericCryptoException("Insufficient salt length");
        }
        final byte[] passwordBytes = ByteUtils.encodeString(password);
        final SecretKey key = KEY_CONVERTOR.convertBytesToSharedSecretKey(passwordBytes);
        final byte[] output = Kmac.kmac256(key, salt, outLength, CRYPTO4_PBKDF_CUSTOM_BYTES);
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(output);
    }



}
