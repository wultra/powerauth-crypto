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
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Universal KDF based on KMAC-256 (Keccak).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Kdf {

    private static final String CRYPTO4_KDF_CUSTOM_STRING = "PA4KDF";
    private static final int KMAC_BIT_LENGTH = 256;

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
            throw new GenericCryptoException("Missing secret key for key derivation.");
        }
        if (index < 0L) {
            throw new GenericCryptoException("Invalid index used for key derivation.");
        }
        final byte[] indexBytes = ByteUtils.encodeLong(index);
        final byte[] data;
        if (context != null) {
            data = ByteUtils.concat(indexBytes, ByteUtils.concatWithSizes(context));
        } else {
            data = indexBytes;
        }
        final byte[] output = kmac256(key, data, outLength, CRYPTO4_KDF_CUSTOM_STRING.getBytes(StandardCharsets.UTF_8));
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(output);
    }

    /**
     * Compute the KMAC256 of the given data using provided secret key, output length and optional customization string.
     *
     * @param key          The secret key, must be a valid {@link SecretKey} with a 256-bit key length.
     * @param data         The input data used for the KMAC.
     * @param outLength    The length of generated output bytes.
     * @param customString An optional customization string, use null value for no customization.
     * @return KMAC256 output byte array.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    static byte[] kmac256(SecretKey key, byte[] data, int outLength, byte[] customString) throws GenericCryptoException {
        if (key == null) {
            throw new GenericCryptoException("Missing secret key for KDF.");
        }
        if (data == null) {
            throw new GenericCryptoException("Missing data for KDF.");
        }
        if (outLength <= 0) {
            throw new GenericCryptoException("Invalid output length for KDF.");
        }
        final KMAC kmac = new KMAC(KMAC_BIT_LENGTH, customString);
        final byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new GenericCryptoException("Secret key encoding is null.");
        }
        kmac.init(new KeyParameter(keyBytes));
        kmac.update(data, 0, data.length);
        final byte[] output = new byte[outLength];
        kmac.doFinal(output, 0, outLength);
        return output;
    }

}
