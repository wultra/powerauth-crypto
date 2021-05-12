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
package io.getlime.security.powerauth.crypto.lib.enums;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * Enum with a derived key identifier and indexes.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public enum PowerAuthDerivedKey {

    /**
     * Value related to the possession factor signature key, value = 1
     */
    SIGNATURE_POSSESSION(1),

    /**
     * Value related to the knowledge factor signature key, value = 2
     */
    SIGNATURE_KNOWLEDGE(2),

    /**
     * Value related to the biometry factor signature key, value = 3
     */
    SIGNATURE_BIOMETRY(3),

    /**
     * Value related to the master transport key, value = 1000
     */
    TRANSPORT(1000),

    /**
     * Value related to the encrypted vault key, value = 2000
     */
    ENCRYPTED_VAULT(2000);

    private final long index;

    private final static Map<Long, PowerAuthDerivedKey> map = new HashMap<>();

    static {
        for (PowerAuthDerivedKey derivedKey : PowerAuthDerivedKey.values()) {
            map.put(derivedKey.index, derivedKey);
        }
    }

    PowerAuthDerivedKey(final long index) {
        this.index = index;
    }

    /**
     * Get enum instance from long value.
     * @param index Enum value.
     * @return Enum instance.
     */
    public static PowerAuthDerivedKey valueOf(long index) {
        return map.get(index);
    }

    /**
     * Get the byte array value of key index.
     * @return Get the byte array value of key index.
     */
    public byte[] getIndex() {
        return ByteBuffer.allocate(16).putLong(0L).putLong(index).array();
    }

}