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
package io.getlime.security.powerauth.crypto.lib.util;

import com.google.common.primitives.Bytes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.UUID;

/**
 * Class used for computing PowerAuth Token digests.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class TokenUtils {

    private KeyGenerator keyGenerator = new KeyGenerator();
    private HMACHashUtilities hmac = new HMACHashUtilities();

    /**
     * Generate random token ID. Use UUID format.
     * @return Random token ID.
     */
    public String generateTokenId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate random token secret, 16 random bytes.
     * @return Random token secret.
     */
    public byte[] generateTokenSecret() {
        return keyGenerator.generateRandomBytes(16);
    }

    /**
     * Generate random token nonce, 16 random bytes.
     * @return Random token nonce.
     */
    public byte[] generateTokenNonce() {
        return keyGenerator.generateRandomBytes(16);
    }

    /**
     * Helper method to get current timestamp for the purpose of token timestamping, encoded as 8 bytes.
     * @return Current timestamp in milliseconds.
     */
    public byte[] generateTokenTimestamp() {
        try {
            return String.valueOf(System.currentTimeMillis()).getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            // ... in case system does not support UTF-8
        }
        return null;
    }

    /**
     * Helper method to convert provided timestamp into 8 bytes, for the purpose of token timestamping.
     * @param timestamp Timestamp to be converted.
     * @return Provided timestamp in milliseconds converted as bytes.
     */
    public byte[] convertTokenTimestamp(long timestamp) {
        try {
            return String.valueOf(timestamp).getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            // ... in case system does not support UTF-8
        }
        return null;
    }

    /**
     * Compute the digest of provided token information using given token secret.
     * @param nonce Token nonce, 16 random bytes.
     * @param timestamp Token timestamp, Unix timestamp format encoded as 8 bytes.
     * @param tokenSecret Token secret, 16 random bytes.
     * @return Token digest computed using provided data bytes with given token secret.
     */
    public byte[] computeTokenDigest(byte[] nonce, byte[] timestamp, byte[] tokenSecret) {
        try {
            byte[] amp = "&".getBytes("UTF-8");
            byte[] data = Bytes.concat(nonce, amp, timestamp);
            return hmac.hash(tokenSecret, data);
        } catch (UnsupportedEncodingException e) {
            // ... in case system does not support UTF-8
        }
        return null;
    }

    /**
     * Validate provided token digest for given input data and provided token secret.
     * @param nonce Token nonce, 16 random bytes.
     * @param timestamp Token timestamp, Unix timestamp format encoded as 8 bytes.
     * @param tokenSecret Token secret, 16 random bytes.
     * @param tokenDigest Token digest, 32 bytes to be validated.
     * @return Token digest computed using provided data bytes with given token secret.
     */
    public boolean validateTokenDigest(byte[] nonce, byte[] timestamp, byte[] tokenSecret, byte[] tokenDigest) {
        return Arrays.equals(computeTokenDigest(nonce, timestamp, tokenSecret), tokenDigest);
    }

}
