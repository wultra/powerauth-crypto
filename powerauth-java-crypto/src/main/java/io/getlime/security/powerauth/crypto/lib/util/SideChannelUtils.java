/*
 * PowerAuth Crypto Library
 * Copyright 2021 Wultra s.r.o.
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

import org.bouncycastle.util.Arrays;

/**
 * Utilities for preventing side channel attacks.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SideChannelUtils {

    private SideChannelUtils() {
        
    }

    /**
     * Compare two byte arrays in constant time.
     * @param bytes1 First byte array.
     * @param bytes2 Second byte array.
     * @return Whether byte arrays are equal.
     */
    public static boolean constantTimeAreEqual(byte[] bytes1, byte[] bytes2) {
        return Arrays.constantTimeAreEqual(bytes1, bytes2);
    }
}
