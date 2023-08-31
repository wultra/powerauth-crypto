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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Simple utility class that provides the basic hash methods.
 * <p>
 * Supported methods:
 * <p>
 * - SHA256
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class Hash {

    private static final Logger logger = LoggerFactory.getLogger(Hash.class);

    /**
     * Compute hash digest for given data using SHA-256.
     * @param originalBytes Original bytes to be hashed.
     * @return Hashed bytes.
     * @throws NoSuchAlgorithmException In case a provided algorithm does not exist.
     */
    private static byte[] hash(byte[] originalBytes) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(originalBytes);
    }

    /**
     * Compute SHA256 hash of provided bytes.
     * @param originalBytes Original bytes.
     * @return SHA256 hash of provided original bytes.
     */
    public static byte[] sha256(byte[] originalBytes) {
        try {
            return hash(originalBytes);
        } catch (NoSuchAlgorithmException ex) {
            logger.warn(ex.getMessage(), ex);
            return null;
        }
    }

    /**
     * Compute SHA256 hash of provided string, that was transferred to data using UTF-8 charset.
     * @param string String to be hashed.
     * @return SHA256 hash of provided string.
     */
    public static byte[] sha256(String string) {
        return sha256(string, StandardCharsets.UTF_8);
    }

    /**
     * Compute SHA256 hash of provided string, that was transferred to data using provided charset.
     * @param string Original string to be hashed.
     * @param charset Charset to be used to convert string to bytes.
     * @return SHA256 hash of provided string.
     */
    public static byte[] sha256(String string, Charset charset) {
        byte[] originalBytes = string.getBytes(charset);
        return sha256(originalBytes);
    }

}
