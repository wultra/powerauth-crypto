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
package io.getlime.security.powerauth.crypto.lib.generator;

import io.getlime.security.powerauth.crypto.lib.api.Counter;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.util.Hash;

/**
 * Implementation of hash based counter.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class HashBasedCounter implements Counter {

    /**
     * Number of bytes used in counter.
     */
    private static final int HASH_COUNTER_RANDOM_BYTES_LENGTH = 16;

    /**
     * Key generator is used for operations with bytes.
     */
    private final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Generate initial counter data.
     * @return Initial counter data.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    @Override
    public byte[] init() throws CryptoProviderException {
        return keyGenerator.generateRandomBytes(HASH_COUNTER_RANDOM_BYTES_LENGTH);
    }

    /**
     * Generate next counter data by hashing current counter data.
     * @param ctrData Current counter data.
     * @return Next counter data.
     */
    public byte[] next(byte[] ctrData) {
        byte[] nextCtrData = Hash.sha256(ctrData);
        if (nextCtrData != null) {
            return keyGenerator.convert32Bto16B(nextCtrData);
        }
        return null;
    }

}
