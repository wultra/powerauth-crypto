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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Simple utility class for HMAC-SHA256 algorithm
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class HMACHashUtilities {

    private static final Logger logger = LoggerFactory.getLogger(HMACHashUtilities.class);

    /**
     * Compute a HMAC-SHA256 of given data with provided key bytes
     * @param key Key for the HMAC-SHA256 algorithm
     * @param data Data for the HMAC-SHA256 algorithm.
     * @return HMAC-SHA256 of given data using given key.
     * @throws GenericCryptoException In case hash computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] hash(byte[] key, byte[] data) throws GenericCryptoException, CryptoProviderException {
        try {
            Mac hmacSha256 = Mac.getInstance("HmacSHA256", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            SecretKey hmacKey = new SecretKeySpec(key, "HmacSHA256");
            hmacSha256.init(hmacKey);
            return hmacSha256.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (InvalidKeyException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Compute a HMAC-SHA256 of given data with provided key bytes
     * @param hmacKey Key for the HMAC-SHA256 algorithm
     * @param data Data for the HMAC-SHA256 algorithm.
     * @return HMAC-SHA256 of given data using given key.
     * @throws GenericCryptoException  In case hash computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] hash(SecretKey hmacKey, byte[] data) throws GenericCryptoException, CryptoProviderException {
        try {
            Mac hmacSha256 = Mac.getInstance("HmacSHA256", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            hmacSha256.init(hmacKey);
            return hmacSha256.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        } catch (InvalidKeyException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

}
