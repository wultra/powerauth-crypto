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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Data reader class provides simple streaming interface usable for
 * data deserialization.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class DataReader {

    private final byte[] data;
    private int offset = 0;

    /**
     * SDK reader constructor.
     * @param data Binary data to read.
     */
    DataReader(byte[] data) {
        this.data = data;
    }

    /**
     * Resets data reader to its initial state.
     */
    public void reset() {
        this.offset = 0;
    }

    /**
     * Returns remaining size available in the stream.
     * @return Remaining size.
     */
    public int remainingSize() {
        return data.length - offset;
    }

    /**
     * Returns current reading offset.
     * @return Current reading offset.
     */
    public int currentOffset() {
        return offset;
    }

    /**
     * Returns true if it's possible to read at least |size| of bytes from stream.
     * @param size Byte size.
     * @return True if reader can read next bytes.
     */
    public boolean canReadSize(int size) {
        return remainingSize() >= size;
    }

    /**
     * Skips required number of bytes in the stream. Returns false, if there's not enough bytes left.
     * @param size Byte size.
     * @return True if skip was successful.
     */
    public boolean skipBytes(int size) {
        if (!canReadSize(size)) {
            return false;
        }
        offset += size;
        return true;
    }

    /**
     * Reads a data object into output byte array.
     * @param expectedSize Expected byte array size or 0 for any size.
     * @return Read data.
     */
    public byte[] readData(int expectedSize) {
        final Integer size = readCount();
        if (size == null) {
            return null;
        }
        if (!canReadSize(size)) {
            return null;
        }
        if (expectedSize > 0 && expectedSize != size) {
            return null;
        }
        byte[] result = Arrays.copyOfRange(data, offset, offset + size);
        offset += size;
        return result;
    }

    /**
     * Reads a string object into output byte array.
     * @return Read string.
     */
    public String readString() {
        final Integer size = readCount();
        if (size == null) {
            return null;
        }
        if (!canReadSize(size)) {
            return null;
        }
        final byte[] strData = Arrays.copyOfRange(data, offset, offset + size);
        offset += size;
        return new String(strData, StandardCharsets.UTF_8);
    }

    /**
     * Reads an exact number of bytes into output byte array. Unlike the {@link #readData(int)} method, this method
     * reads just exact number of bytes from the stream, without any size marker.
     * @param size Byte size.
     * @return Read bytes.
     */
    public byte[] readRaw(int size) {
        if (!canReadSize(size)) {
            return null;
        }
        final byte[] result = Arrays.copyOfRange(data, offset, offset + size);
        offset += size;
        return result;
    }

    /**
     * Reads one byte into output byte array.
     * @return Read byte.
     */
    public Byte readByte() {
        if (!canReadSize(1)) {
            return null;
        }
        byte result = data[offset];
        offset++;
        return result;
    }

    /**
     * Returns count from data stream.
     * @return Count.
     */
    public Integer readCount() {
        final Byte firstByte = readByte();
        if (firstByte == null) {
            return null;
        }
        final int byte1u = Byte.toUnsignedInt(firstByte);
        final int marker = byte1u & 0xC0;
        if (marker == 0x00 || marker == 0x40) {
            return byte1u;
        }
        // marker is 2 or 3, that means that we need 1 or 3 more bytes
        final int additionalByteCount = marker == 0xC0 ? 3 : 1;
        final byte[] remainingBytes = readRaw(additionalByteCount);
        if (remainingBytes == null) {
            return null;
        }
        final int byte2u = Byte.toUnsignedInt(remainingBytes[0]);
        if (marker == 0xC0) {
            // 4 bytes
            int byte3u = Byte.toUnsignedInt(remainingBytes[1]);
            int byte4u = Byte.toUnsignedInt(remainingBytes[2]);
            return (byte1u & 0x3F) << 24 |
                    byte2u << 16 |
                    byte3u << 8 |
                    byte4u;
        } else {
            // 2 bytes
            return (byte1u & 0x3F) << 8 |
                    byte2u;
        }
    }
}
