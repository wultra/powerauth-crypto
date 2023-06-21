/*
 * PowerAuth Crypto Library
 * Copyright 2023 Wultra s.r.o.
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

import java.nio.ByteBuffer;

/**
 * A utility class for handling ECIES data.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public final class EciesUtils {

    /**
     * Private constructor.
     */
    private EciesUtils() {
    }

    /**
     * Resolve MAC data for ECIES request or response MAC validation.
     *
     * @param sharedInfo2        Parameter sharedInfo2 for ECIES.
     * @param encryptedData      Encypted data.
     * @param nonce              Nonce, required for protocol V3.1+.
     * @param associatedData     Data associated with ECIES request or response, required for protocol V3.2+
     * @param timestamp     ECIES request timestamp bytes, required for protocol V3.2+
     * @param ephemeralKeyPublic Ephemeral public key.
     * @return Resolved MAC data.
     */
    public static byte[] resolveMacData(byte[] sharedInfo2, byte[] encryptedData, byte[] nonce,
                                        byte[] associatedData, Long timestamp, byte[] ephemeralKeyPublic) {
        // Resolve MAC data based on protocol version
        if (timestamp == null) {
            // Protocol V3.1 and older
            return ByteUtils.concat(encryptedData, sharedInfo2);
        }
        // Protocol V3.2+
        final byte[] timestampBytes = ByteBuffer.allocate(8).putLong(timestamp).array();
        final byte[] ad = ByteUtils.concat(associatedData, ByteUtils.concatWithSizes(nonce, timestampBytes, ephemeralKeyPublic));
        return ByteUtils.concat(ad, encryptedData, sharedInfo2);
    }

    /**
     * Generate timestamp for ECIES request/response.
     *
     * @return Timestamp bytes to use for ECIES encryption.
     */
    public static long generateTimestamp() {
        // Protocol V3.2+
        return System.currentTimeMillis();
    }
}
