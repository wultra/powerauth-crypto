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
package io.getlime.security.powerauth.crypto.lib.encryptor.ecies.kdf;

import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.crypto.lib.util.Hash;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Implementation of X9.63 KDF function with SHA256 digest type.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class KdfX9_63 {

    /**
     * Derive a new key using X9.63 with SHA256 digest.
     * @param secret Secret key to be used as the derivation base key.
     * @param sharedInfo Extra information used for derived key computation.
     * @param outputBytes Requested size of the key.
     * @return Derived key using the X9.63 KDF with SHA256 digest.
     * @throws GenericCryptoException In case key derivation fails.
     */
    public static byte[] derive(byte[] secret, byte[] sharedInfo, int outputBytes) throws GenericCryptoException {
        if (secret == null) {
            throw new GenericCryptoException("Missing secret for KDF X9.63");
        }
        byte[] result = new byte[0];
        byte[] round = new byte[secret.length + 4 + (sharedInfo == null ? 0 : sharedInfo.length)];
        byte[] temp;
        byte[] counter;
        int i = 1;
        while (result.length < outputBytes) {
            // Copy secret
            System.arraycopy(secret, 0, round, 0, secret.length);
            // Copy counter
            counter = ByteBuffer.allocate(4).putInt(i).array();
            System.arraycopy(counter, 0, round, secret.length, 4);
            // Copy additional sharedInfo
            if (sharedInfo != null) {
                System.arraycopy(sharedInfo, 0, round, secret.length + 4, sharedInfo.length);
            }
            // Hash the value
            temp = Hash.sha256(round);
            if (temp == null || temp.length == 0) {
                result = new byte[0];
                break;
            }
            // Append working batch to result
            result = ByteUtils.concat(result, temp);
            ++i;
        }
        // Trim the array to the desired length
        if (result.length > outputBytes) {
            result = Arrays.copyOf(result, outputBytes);
        }
        return result;
    }

}
