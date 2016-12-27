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

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Simple utility class for HMAC-SHA256 algorithm
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
public class HMACHashUtilities {

    /**
     * Compute a HMAC-SHA256 of given data with provided key bytes
     * @param key Key for the HMAC-SHA256 algorithm
     * @param data Data for the HMAC-SHA256 algorithm.
     * @return HMAC-SHA256 of given data using given key.
     */
    public byte[] hash(byte[] key, byte[] data) {
        try {
            Mac hmacSha256 = Mac.getInstance("HmacSHA256", PowerAuthConfiguration.INSTANCE.getKeyConvertor().getProviderName());
            SecretKey hmacKey = new SecretKeySpec(key, "HmacSHA256");
            hmacSha256.init(hmacKey);
            byte[] derivedKey = hmacSha256.doFinal(data);
            return derivedKey;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            Logger.getLogger(HMACHashUtilities.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

}
