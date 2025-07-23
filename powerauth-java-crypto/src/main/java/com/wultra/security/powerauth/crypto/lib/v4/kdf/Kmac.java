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

package com.wultra.security.powerauth.crypto.lib.v4.kdf;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;

/**
 * Keccak Message Authentication Code.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Kmac {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private static final int KMAC_BIT_LENGTH = 256;

    /**
     * Compute the KMAC256 of the given data using provided secret key, output length and optional customization string.
     *
     * @param key          The secret key, must be a valid {@link SecretKey}with a 256-bit key length.
     * @param data         The input data used for the KMAC.
     * @param customString An optional customization string, use null value for no customization.
     * @return KMAC256 output byte array.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public static byte[] kmac256(SecretKey key, byte[] data, byte[] customString) throws GenericCryptoException {
        final byte[] keyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(key);
        return kmac256(keyBytes, data, customString, 32);
    }

    /**
     * Compute the KMAC256 of the given data using provided secret key, output length and optional customization string.
     *
     * @param key          The secret key, must be a valid {@link SecretKey}with a 256-bit key length.
     * @param data         The input data used for the KMAC.
     * @param customString An optional customization string, use null value for no customization.
     * @param outLength    The length of generated output bytes.
     * @return KMAC256 output byte array.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public static byte[] kmac256(SecretKey key, byte[] data, byte[] customString, int outLength) throws GenericCryptoException {
        final byte[] keyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(key);
        return kmac256(keyBytes, data, customString, outLength);
    }

    /**
     * Compute the KMAC256 of the given data using provided secret key, output length and optional customization string.
     *
     * @param keyBytes     Encoded secret key, must be a byte[] with a 256-bit key length.
     * @param data         The input data used for the KMAC.
     * @param customString An optional customization string, use null value for no customization.
     * @return KMAC256 output byte array.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public static byte[] kmac256(byte[] keyBytes, byte[] data, byte[] customString) throws GenericCryptoException {
        return kmac256(keyBytes, data, customString, 32);
    }

    /**
     * Compute the KMAC256 of the given data using provided secret key, output length and optional customization string.
     *
     * @param keyBytes     Encoded secret key, must be a byte[] with a 256-bit key length.
     * @param data         The input data used for the KMAC.
     * @param customString An optional customization string, use null value for no customization.
     * @param outLength    The length of generated output bytes.
     * @return KMAC256 output byte array.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public static byte[] kmac256(byte[] keyBytes, byte[] data, byte[] customString, int outLength) throws GenericCryptoException {
        if (keyBytes == null) {
            throw new GenericCryptoException("Missing secret key for KMAC");
        }
        if (data == null) {
            throw new GenericCryptoException("Missing data for KDF");
        }
        if (outLength <= 0) {
            throw new GenericCryptoException("Invalid output length for KDF");
        }
        final KMAC kmac = new KMAC(KMAC_BIT_LENGTH, customString);
        kmac.init(new KeyParameter(keyBytes));
        kmac.update(data, 0, data.length);
        final byte[] output = new byte[outLength];
        kmac.doFinal(output, 0, outLength);
        return output;
    }

}
