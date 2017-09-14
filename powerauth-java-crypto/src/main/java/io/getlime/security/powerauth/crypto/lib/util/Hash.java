/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Simple utility class that provides the basic hash methods.
 *
 * Supported methods:
 *
 * - SHA1
 * - SHA256
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class Hash {

    /**
     * Compute hash digest for given data using provided algorithm.
     * @param originalBytes Original bytes to be hashed.
     * @param algorithm Algorithm to be used to compute hash.
     * @return Hashed bytes.
     * @throws NoSuchAlgorithmException In case a provided algorithm does not exist.
     */
    private static byte[] hash(byte[] originalBytes, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(originalBytes);
    }

    /**
     * Compute SHA1 hash of provided bytes.
     * @param originalBytes Original bytes.
     * @return SHA1 hash of provided original bytes.
     */
    public static byte[] sha1(byte[] originalBytes) {
        try {
            return hash(originalBytes, "SHA-1");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Compute SHA1 hash of provided string, that was transferred to data using UTF-8 charset.
     * @param string String to be hashed.
     * @return SHA1 hash of provided string.
     */
    public static byte[] sha1(String string) {
        try {
            return sha1(string, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    /**
     * Compute SHA1 hash of provided string, that was transferred to data using provided charset.
     * @param string Original string to be hashed.
     * @param charset Charset to be used to convert string to bytes.
     * @return SHA1 hash of provided string.
     * @throws UnsupportedEncodingException In case invalid charset is provided.
     */
    public static byte[] sha1(String string, String charset) throws UnsupportedEncodingException {
        byte[] originalBytes = string.getBytes(charset);;
        return sha1(originalBytes);
    }

    /**
     * Compute SHA256 hash of provided bytes.
     * @param originalBytes Original bytes.
     * @return SHA256 hash of provided original bytes.
     */
    public static byte[] sha256(byte[] originalBytes) {
        try {
            return hash(originalBytes, "SHA-256");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Compute SHA256 hash of provided string, that was transferred to data using UTF-8 charset.
     * @param string String to be hashed.
     * @return SHA256 hash of provided string.
     */
    public static byte[] sha256(String string) {
        try {
            return sha256(string, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    /**
     * Compute SHA256 hash of provided string, that was transferred to data using provided charset.
     * @param string Original string to be hashed.
     * @param charset Charset to be used to convert string to bytes.
     * @return SHA256 hash of provided string.
     * @throws UnsupportedEncodingException In case invalid charset is provided.
     */
    public static byte[] sha256(String string, String charset) throws UnsupportedEncodingException {
        byte[] originalBytes = string.getBytes(charset);;
        return sha1(originalBytes);
    }

}
