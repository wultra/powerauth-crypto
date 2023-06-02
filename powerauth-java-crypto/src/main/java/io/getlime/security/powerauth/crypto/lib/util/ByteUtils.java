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

import com.google.common.primitives.Bytes;

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
     * @param args Byte arrays to concatenate.
     * @return Concatenated byte array.
     */
    public static byte[] concat(byte[]... args) {
        byte[] result = new byte[0];
        for (byte[] component : args) {
            if (component != null) {
                result = Bytes.concat(result, component);
            }
        }
        return result;
    }

    /**
     * Join multiple byte arrays, including each component size.
     * @param args Byte arrays to join.
     * @return Joined byte array.
     */
    public static byte[] join(byte[]... args) {
        byte[] result = new byte[0];
        for (byte[] component : args) {
            if (component != null) {
                result = concat(result, encode(component.length), component);
            } else {
                result = concat(result, encode(0));
            }
        }
        return result;
    }

    /**
     * Join multiple strings and convert them into a byte array, include each string length.
     * @param args Strings to join.
     * @return Byte array with joined strings.
     */
    public static byte[] joinStrings(String... args) {
        byte[] result = new byte[0];
        for (String component : args) {
            if (component != null) {
                byte[] componentBytes = encode(component);
                result = ByteUtils.concat(result, encode(componentBytes.length), componentBytes);
            } else {
                result = ByteUtils.concat(result, encode(0));
            }
        }
        return result;
    }

    /**
     * Encode a short number into a byte array.
     * @param n Short number to encode.
     * @return Byte array.
     */
    public static byte[] encode(short n) {
        return ByteBuffer.allocate(2).putShort(n).array();
    }

    /**
     * Encode an int number into a byte array.
     * @param n Int number to encode.
     * @return Byte array.
     */
    public static byte[] encode(int n) {
        return ByteBuffer.allocate(4).putInt(n).array();
    }

    /**
     * Encode a long number into a byte array.
     * @param n Long number to encode.
     * @return Byte array.
     */
    public static byte[] encode(long n) {
        return ByteBuffer.allocate(8).putLong(n).array();
    }

    /**
     * Encode a String into a byte array.
     * @param s String to encode.
     * @return Byte array.
     */
    public static byte[] encode(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

}