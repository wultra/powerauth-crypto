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
package com.wultra.security.powerauth.crypto.server.util;

import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.HMACHashUtilities;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kmac;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * This is a helper class that provides utility methods for computing various data digests.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class DataDigest {

    private static final byte[] KMAC_DATA_DIGEST_CUSTOM_BYTES = "PA4DIGEST_DATA".getBytes(StandardCharsets.UTF_8);

    private static final Logger logger = LoggerFactory.getLogger(DataDigest.class);

    /**
     * Data digest result.
     */
    public static class Result {

        private final String digest;
        private final byte[] salt;

        Result(String digest, byte[] salt) {
            this.digest = digest;
            this.salt = salt;
        }

        /**
         * Get data digest.
         * @return Data digest.
         */
        public String getDigest() {
            return digest;
        }

        /**
         * Get salt used for creating the data digest.
         * @return Salt used for creating the data digest.
         */
        public byte[] getSalt() {
            return salt;
        }

    }

    private static final int AUTHORIZATION_CODE_LENGTH_MIN = 4;
    private static final int AUTHORIZATION_CODE_LENGTH_MAX = 9;
    private static final int AUTHORIZATION_CODE_LENGTH = 8;

    private final HMACHashUtilities hmac = new HMACHashUtilities();

    private final int authorizationCodeLength;

    /**
     * Initializes the data digest instance that produces digest of length 8.
     */
    public DataDigest() {
        this.authorizationCodeLength = AUTHORIZATION_CODE_LENGTH;
    }

    /**
     * Initializes the data digest instance that produces digest of specified length. The length must be between 4 and 9.
     * The digest cannot be shorter than 4 due to lack of entropy in shorter codes. The digest cannot be longer than 9 digits
     * since the internal implementation uses <code>int</code>, with a 64 bit range.
     *
     * @param length Length of the resulting digest.
     * @throws GenericCryptoException In case the length is not in the allowed range - between 4 and 9 digits.
     */
    public DataDigest(int length) throws GenericCryptoException {
        if (length < AUTHORIZATION_CODE_LENGTH_MIN || length > AUTHORIZATION_CODE_LENGTH_MAX) {
            throw new GenericCryptoException("Invalid length of the data digest: " + length);
        }
        this.authorizationCodeLength = length;
    }
    
    /**
     * Data digest of the list with string elements. Data is first normalized (items concatenated
     * by '&amp;' character), then a random key is generated and hash (HMAC-SHA256) is computed. Finally,
     * the resulting MAC is decimalized to the signature of a length 8 numeric digits.
     *
     * @deprecated use {@link #generateDigest(String, List)}
     *
     * @param items Items to be serialized into digest.
     * @return Digest fo provided data, including seed used to compute that digest.
     * @throws GenericCryptoException In case cryptography fails.
     */
    @Deprecated
    public Result generateDigest(List<String> items) throws GenericCryptoException {
        return generateDigest("3.3", items);
    }

    /**
     * Data digest of the list with string elements. Data is first normalized (items concatenated
     * by '&amp;' character), then a random key is generated and hash (HMAC-SHA256) is computed. Finally,
     * the resulting MAC is decimalized to the signature of a length 8 numeric digits.
     *
     * @param version Cryptography protocol version.
     * @param items Items to be serialized into digest.
     * @return Digest fo provided data, including seed used to compute that digest.
     * @throws GenericCryptoException In case cryptography fails.
     */
    public Result generateDigest(String version, List<String> items) throws GenericCryptoException {
        if (version == null) {
            throw new GenericCryptoException("Missing protocol version when calculating digest");
        }
        if (items == null || items.isEmpty()) {
            throw new GenericCryptoException("Missing data when calculating digest");
        }
        try {
            final byte[] operationData = String.join("&", items).getBytes(StandardCharsets.UTF_8);
            final byte[] randomKey = new KeyGenerator().generateRandomBytes(16);
            final byte[] otpHash = generateDigest(version, operationData, randomKey);
            final BigInteger otp = new BigInteger(otpHash).mod(BigInteger.TEN.pow(authorizationCodeLength));
            final String digitFormat = "%" + String.format("%02d", authorizationCodeLength) + "d";
            final String digest = String.format(digitFormat, otp);
            return new Result(digest, randomKey);
        } catch (GenericCryptoException | CryptoProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            return null;
        }
    }

    private byte[] generateDigest(String version, byte[] operationData, byte[] key) throws GenericCryptoException, CryptoProviderException {
        return switch (version) {
            case "3.0", "3.1", "3.2", "3.3" -> hmac.hash(key, operationData);
            case "4.0" -> Kmac.kmac256(key, operationData, KMAC_DATA_DIGEST_CUSTOM_BYTES);
            default -> throw new GenericCryptoException("Unsupported protocol version: " + version);
        };
    }

}
