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
package com.wultra.security.powerauth.crypto.lib.generator;

import com.wultra.security.powerauth.crypto.lib.api.Counter;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.Hash;
import com.wultra.security.powerauth.crypto.lib.v4.hash.Sha3;

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
    private static final int HASH_COUNTER_RANDOM_BYTES_LENGTH_V3 = 16;
    private static final int HASH_COUNTER_RANDOM_BYTES_LENGTH_V4 = 32;

    /**
     * Key generator is used for operations with bytes.
     */
    private final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    /**
     * Protocol version.
     */
    private final String version;

    /**
     * Constructor with version.
     *
     * @param version Protocol version.
     * @throws GenericCryptoException Thrown in case version is not specified.
     */
    public HashBasedCounter(String version) throws GenericCryptoException {
        if (version == null) {
            throw new GenericCryptoException("Missing protocol version");
        }
        this.version = version;
    }

    @Override
    public byte[] init() throws CryptoProviderException, GenericCryptoException {
        final byte[] ctrData;
        switch (version) {
            case "3.0", "3.1", "3.2", "3.3" -> ctrData = KEY_GENERATOR.generateRandomBytes(HASH_COUNTER_RANDOM_BYTES_LENGTH_V3);
            case "4.0" -> ctrData = KEY_GENERATOR.generateRandomBytes(HASH_COUNTER_RANDOM_BYTES_LENGTH_V4);
            default -> throw new GenericCryptoException("Unsupported version: " + version);
        }
        return ctrData;
    }

    @Override
    public byte[] next(byte[] ctrData) throws GenericCryptoException {
        if (ctrData == null) {
            throw new GenericCryptoException("Missing input counter data");
        }
        final byte[] nextCtrData;
        switch (version) {
            case "3.0", "3.1", "3.2", "3.3" -> {
                final byte[] nextData = Hash.sha256(ctrData);
                if (nextData == null) {
                    throw new GenericCryptoException("Hash calculation failed");
                }
                nextCtrData = KEY_GENERATOR.convert32Bto16B(nextData);
            }
            case "4.0" -> nextCtrData = Sha3.hash256(ctrData);
            default -> throw new GenericCryptoException("Unsupported version: " + version);
        }
        return nextCtrData;
    }

}
