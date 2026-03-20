/*
 * PowerAuth Crypto Library
 * Copyright 2026 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.sdk;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Test for {@link DataWriter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class DataWriterTest {

    @Test
    void testCountWrite() {
        final String countsGeneratedBySdk = "AAF/gICA/4EAgQG//8AAQADAAP//wAEAAMD////BAAAAwQIDBNAgMED/////";
        final DataReader reader = new DataReader(Base64.decode(countsGeneratedBySdk));
        final List<Integer> expectedCounts = new ArrayList<>();
        expectedCounts.add(0);
        expectedCounts.add(1);
        expectedCounts.add(0x7F);
        expectedCounts.add(0x80);
        expectedCounts.add(0xFF);
        expectedCounts.add(0x100);
        expectedCounts.add(0x101);
        expectedCounts.add(0x3FFF);
        expectedCounts.add(0x4000);
        expectedCounts.add(0xFFFF);
        expectedCounts.add(0x10000);
        expectedCounts.add(0xFFFFFF);
        expectedCounts.add(0x1000000);
        expectedCounts.add(0x1020304);
        expectedCounts.add(0x10203040);
        expectedCounts.add(0x3FFFFFFF);
        expectedCounts.forEach(countExpected -> {
            final int countExpectedFromSdk = reader.readCount();
            // Attempt to write value into serialized data, compare with expected hex value
            final DataWriter dataWriter = new DataWriter();
            dataWriter.writeCount(Math.toIntExact(countExpected));
            final byte[] serialized = dataWriter.getSerializedData();
            // Attempt to read value from serialized data, it should match the expected count from SDK
            final DataReader sdkDataReader = new DataReader(serialized);
            final int countDeserialized = sdkDataReader.readCount();
            assertEquals(countExpected, countDeserialized);
            assertEquals(countExpectedFromSdk, countDeserialized);
        });
    }

    @Test
    void testCountWriteInvalid() {
        final DataWriter dataWriter = new DataWriter();
        assertFalse(dataWriter.writeCount(1073741824));
        assertEquals(0, dataWriter.getSerializedData().length);
    }

    @Test
    void testCountWriteInvalidMaxInt() {
        final DataWriter dataWriter = new DataWriter();
        assertFalse(dataWriter.writeCount(Integer.MAX_VALUE));
        assertEquals(0, dataWriter.getSerializedData().length);
    }

    @Test
    void testCountWriteInvalidNegative() {
        final DataWriter dataWriter = new DataWriter();
        assertFalse(dataWriter.writeCount(-1));
        assertEquals(0, dataWriter.getSerializedData().length);
    }

    @Test
    void testCountWriteInvalidMinInt() {
        final DataWriter dataWriter = new DataWriter();
        assertFalse(dataWriter.writeCount(Integer.MIN_VALUE));
        assertEquals(0, dataWriter.getSerializedData().length);
    }

}
