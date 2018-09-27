/*
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

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CRC16Test {

    private CRC16 crc16;

    @Before
    public void setUp() {
        crc16 = new CRC16();
    }

    @Test
    public void testCRC16WithReset() {
        assertEquals(50923, computeCRC16("iV6jP5Xr0z", true));
        assertEquals(10082, computeCRC16("dD5HnVp68n", true));
        assertEquals(20455, computeCRC16("Fuu5G0DUJR", true));
        assertEquals(13179, computeCRC16("iPeHJFjSCh", true));
        assertEquals(55500, computeCRC16("vBS8tFjAOx", true));
        assertEquals(58775, computeCRC16("iJA6cuvi4q", true));
        assertEquals(58683, computeCRC16("MeIWdZggy0", true));
        assertEquals(63310, computeCRC16("kNu1i4Fben", true));
        assertEquals(32651, computeCRC16("B5IQaGOYSv", true));
        assertEquals(43790, computeCRC16("E31xKoJqXA", true));
    }

    @Test
    public void testCRC16WithoutReset() {
        assertEquals(43807, computeCRC16("SVVqcvxwIr", false));
        assertEquals(31786, computeCRC16("5BlzhKRrbS", false));
        assertEquals(33751, computeCRC16("4It3gbOUil", false));
        assertEquals(38709, computeCRC16("d114VnQMPt", false));
        assertEquals(41549, computeCRC16("2y9MrpsTHd", false));
        assertEquals(60241, computeCRC16("A8SwsnadQr", false));
        assertEquals(59417, computeCRC16("pBFaVscMaF", false));
        assertEquals(32027, computeCRC16("VRCFJDt5M1", false));
        assertEquals(54413, computeCRC16("JC1JWvmr5v", false));
        assertEquals(11983, computeCRC16("mJkRVaxR7T", false));
    }

    private long computeCRC16(String inputData, boolean reset) {
        if (reset) {
            crc16.reset();
        }
        crc16.update(inputData.getBytes(), 0, inputData.length());
        return crc16.getValue();
    }

}
