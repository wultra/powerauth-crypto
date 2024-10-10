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
import java.nio.charset.StandardCharsets;

/**
 * A utility class for handling byte array transformations.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public final class ByteUtils {

    /**
     * Private constructor.
     */
    private ByteUtils() {
    }

    /**
     * Concatenate multiple byte arrays.
     * @param arrays Byte arrays to concatenate.
     * @return Concatenated byte array.
     */
    public static byte[] concat(byte[]... arrays) {
        return concatInternal(arrays);
    }

    /**
     * Concatenate multiple byte arrays, including each component size.
     * Sample output byte array structure: [size1][array1][size2][array2]
     * In case byte array is empty, each empty component is encoded as: [0]
     *
     * @param arrays Byte arrays to join.
     * @return Joined byte array.
     */
    public static byte[] concatWithSizes(byte[]... arrays) {
        byte[] result = new byte[0];
        for (byte[] component : arrays) {
            if (component != null) {
                result = concat(result, encodeInt(component.length), component);
            } else {
                result = concat(result, encodeInt(0));
            }
        }
        return result;
    }

    /**
     * Concatenate multiple strings and convert them into a byte array, include each string length.
     * @param strings Strings to join.
     * @return Byte array with joined strings.
     */
    public static byte[] concatStrings(String... strings) {
        byte[] result = new byte[0];
        for (String component : strings) {
            if (component != null) {
                byte[] componentBytes = encodeString(component);
                result = concat(result, encodeInt(componentBytes.length), componentBytes);
            } else {
                result = concat(result, encodeInt(0));
            }
        }
        return result;
    }

    /**
     * Encode a short number into a byte array.
     * @param n Short number to encode.
     * @return Byte array.
     */
    public static byte[] encodeShort(short n) {
        return ByteBuffer.allocate(2).putShort(n).array();
    }

    /**
     * Encode an int number into a byte array.
     * @param n Int number to encode.
     * @return Byte array.
     */
    public static byte[] encodeInt(int n) {
        return ByteBuffer.allocate(4).putInt(n).array();
    }

    /**
     * Encode a long number into a byte array.
     * @param n Long number to encode.
     * @return Byte array.
     */
    public static byte[] encodeLong(long n) {
        return ByteBuffer.allocate(8).putLong(n).array();
    }

    /**
     * Encode a String into a byte array.
     * @param s String to encode.
     * @return Byte array.
     */
    public static byte[] encodeString(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Returns the values from each provided array combined into a single array. For example, {@code
     * concat(new byte[] {a, b}, new byte[] {}, new byte[] {c}} returns the array {@code {a, b, c}}.
     *
     * @param arrays zero or more {@code byte} arrays
     * @return a single array containing all the values from the source arrays, in order
     */
    private static byte[] concatInternal(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                length += array.length;
            }
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                System.arraycopy(array, 0, result, pos, array.length);
                pos += array.length;
            }
        }
        return result;
    }
}