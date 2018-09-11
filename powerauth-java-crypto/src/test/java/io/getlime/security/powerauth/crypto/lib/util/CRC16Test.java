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
    public void testCRC16() {
        assertEquals(43807, computeCRC16("SVVqcvxwIr"));
        assertEquals(31786, computeCRC16("5BlzhKRrbS"));
        assertEquals(33751, computeCRC16("4It3gbOUil"));
        assertEquals(38709, computeCRC16("d114VnQMPt"));
        assertEquals(41549, computeCRC16("2y9MrpsTHd"));
        assertEquals(60241, computeCRC16("A8SwsnadQr"));
        assertEquals(59417, computeCRC16("pBFaVscMaF"));
        assertEquals(32027, computeCRC16("VRCFJDt5M1"));
        assertEquals(54413, computeCRC16("JC1JWvmr5v"));
        assertEquals(11983, computeCRC16("mJkRVaxR7T"));
    }

    private long computeCRC16(String inputData) {
        crc16.update(inputData.getBytes(), 0, inputData.length());
        return crc16.getValue();
    }

}
