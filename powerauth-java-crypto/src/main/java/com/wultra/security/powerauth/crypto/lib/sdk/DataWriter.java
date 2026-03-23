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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Data writer class provides simple streaming interface usable for
 * data serialization.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class DataWriter {

    private static final Logger logger = LoggerFactory.getLogger(DataWriter.class);

    private final ByteArrayOutputStream os = new ByteArrayOutputStream();

    /**
     * Resets data writer object to its initial state.
     */
    public void reset() {
        os.reset();
    }

    /**
     * Writes one byte to the stream.
     * @param b Byte to write.
     */
    public void writeByte(byte b) {
        os.write(b);
    }

    /**
     * Writes number of bytes in byte range and actual
     * data to the stream. The size of range must not exceed
     * value returned from {@link #getMaxCount()} method.
     * @param bytes Bytes to write.
     */
    public void writeData(byte[] bytes) {
        if (!writeCount(bytes.length)) {
            return;
        }
        writeRaw(bytes);
    }

    /**
     * Writes number of characters in string and actual content
     * of string to the data stream. The length of string must
     * not exceed value returned from {@link #getMaxCount()} method.
     * @param str String to write.
     */
    public void writeString(String str) {
        writeData(str.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Writes only the content of byte range to the data stream.
     * Unlike the {@link #writeData(byte[])}, this method doesn't store number of bytes
     * as a size marker. It's up to you, how you determine the size
     * of sequence during the data reading.
     * @param bytes Data bytes.
     */
    public void writeRaw(byte[] bytes) {
        try {
            os.write(bytes);
        } catch (IOException e) {
            logger.warn(e.getMessage(), e);
        }
    }

    /**
     * Writes a count to the stream in optimized binary format. The count
     * parameter must be less or equal than value returned from
     * {@link #getMaxCount()} method.
     *
     * You should prefer this method for counter-type values over the writing
     * 32-bit or 64-bit values to the stream, because it usually produces a shorter byte
     * streams. For example, if count value is lesser than 128, then just
     * one byte is serialized.
     * @param count Count value to write.
     */
    public boolean writeCount(int count) {
        // The SDK expects unsigned values, convert int to unsigned long for the byte operations
        if (count < 0) {
            logger.warn("Count is invalid: {}", count);
        }
        long n = Integer.toUnsignedLong(count);
        if (n <= 0x7F) {
            writeByte((byte) n);
        } else if (n <= 0x3FFF) {
            writeByte((byte) (((n >> 8 ) & 0x3F) | 0x80));
            writeByte((byte) (n        & 0xFF));
        } else if (n <= 0x3FFFFFFF) {
            writeByte((byte) (((n >> 24) & 0x3F) | 0xC0));
            writeByte((byte) ((n >> 16) & 0xFF));
            writeByte((byte) ((n >> 8 ) & 0xFF));
            writeByte((byte) (n        & 0xFF));
        } else {
            logger.warn("Count is too large: {}", n);
            return false;
        }
        return true;
    }

    /**
     * Returns serialized data.
     * @return Serialized data.
     */
    public byte[] getSerializedData() {
        return os.toByteArray();
    }

    /**
     * Returns maximum supported value which can be serialized as
     * a counter. The returned value is the same for all supported
     * platforms and CPU architectures.
     * @return Maximum count value.
     */
    public int getMaxCount() {
        return 0x3FFFFFFF;
    }

}