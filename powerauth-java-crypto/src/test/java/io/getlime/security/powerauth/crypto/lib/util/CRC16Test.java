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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CRC16Test {

    private static CRC16 crc16;

    @BeforeAll
    public static void setUp() {
        crc16 = new CRC16();
    }

    @Test
    public void testCRC16() {
        assertEquals(0xC6EB, computeCRC16("iV6jP5Xr0z"));
        assertEquals(0x2762, computeCRC16("dD5HnVp68n"));
        assertEquals(0x4FE7, computeCRC16("Fuu5G0DUJR"));
        assertEquals(0x337B, computeCRC16("iPeHJFjSCh"));
        assertEquals(0xD8CC, computeCRC16("vBS8tFjAOx"));
        assertEquals(0xE597, computeCRC16("iJA6cuvi4q"));
        assertEquals(0xE53B, computeCRC16("MeIWdZggy0"));
        assertEquals(0x843D, computeCRC16("The quick brown fox jumps over the lazy dog."));
        assertEquals(0xA8E2, computeCRC16("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
                + "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, "
                + "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo "
                + "consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse "
                + "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat "
                + "non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."));
    }

    private long computeCRC16(String inputData) {
        crc16.reset();
        crc16.update(inputData.getBytes(), 0, inputData.length());
        return crc16.getValue();
    }

}
