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
package io.getlime.security.powerauth.crypto.server.util;

import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * This is a helper class that provides utility methods for computing various data digests.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class DataDigest {

    /**
     * Data digest result.
     */
    public class Result {

        private final String digest;
        private final byte[] salt;

        Result(String digest, byte[] salt) {
            this.digest = digest;
            this.salt = salt;
        }

        public String getDigest() {
            return digest;
        }

        public byte[] getSalt() {
            return salt;
        }

    }

    private static final int AUTHORIZATION_CODE_LENGTH = 8;

    private final HMACHashUtilities hmac = new HMACHashUtilities();

    /**
     * Data digest of the list with string elements. Data is first normalized (items concatenated
     * by '&amp;' character), then a random key is generated and hash (HMAC-SHA256) is computed. Finally,
     * the resulting MAC is decimalized to the signature of a length 8 numeric digits.
     *
     * In case the digest could not be computed, null value is returned.
     *
     * @param items Items to be serialized into digest.
     * @return Digest fo provided data, including seed used to compute that digest.
     */
    public Result generateDigest(List<String> items) {
        if (items.size() == 0) {
            return null;
        }
        byte[] operationData = String.join("&", items).getBytes(StandardCharsets.UTF_8);
        byte[] randomKey = new KeyGenerator().generateRandomBytes(16);
        try {
            byte[] otpHash = hmac.hash(randomKey, operationData);
            BigInteger otp = new BigInteger(otpHash).mod(BigInteger.TEN.pow(AUTHORIZATION_CODE_LENGTH));
            String digitFormat = "%" + String.format("%02d", AUTHORIZATION_CODE_LENGTH) + "d";
            String digest = String.format(digitFormat, otp);
            return new Result(digest, randomKey);
        } catch (GenericCryptoException | CryptoProviderException ex) {
            return null;
        }
    }

}
