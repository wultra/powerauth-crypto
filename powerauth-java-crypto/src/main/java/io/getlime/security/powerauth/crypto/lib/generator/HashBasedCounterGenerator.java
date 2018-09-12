/*
 * Copyright 2016 Wultra s.r.o.
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

import io.getlime.security.powerauth.crypto.lib.util.Hash;

/**
 * Generator of hash based counter.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class HashBasedCounterGenerator {

    /**
     * Number of bytes used in counter.
     */
    private static final int HASH_COUNTER_RANDOM_BYTES_LENGTH = 16;

    /**
     * Key generator is used for conversion of bytes.
     */
    private final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Generate initial counter value.
     * @return Initial counter value.
     */
    public byte[] generateInitialValue() {
        return keyGenerator.generateRandomBytes(HASH_COUNTER_RANDOM_BYTES_LENGTH);
    }

    /**
     * Generate next counter value by hashing current counter value.
     * @param currentValue Current counter value.
     * @return Next counter value.
     */
    public byte[] generateNextValue(byte[] currentValue) {
        byte[] hashedValue = Hash.sha256(currentValue);
        return keyGenerator.convert32Bto16B(hashedValue);
    }
}
