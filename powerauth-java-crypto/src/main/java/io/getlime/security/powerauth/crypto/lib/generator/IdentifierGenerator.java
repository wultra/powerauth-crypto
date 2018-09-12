/*
 * Copyright 2016 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.generator;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Longs;
import io.getlime.security.powerauth.crypto.lib.util.CRC16;

import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * Generator of identifiers used in PowerAuth protocol.
 *
 * @author Petr Dvorak
 *
 */
public class IdentifierGenerator {

    /**
     * Default length of Activation ID Short and Activation OTP.
     */
    private static final int BASE32_KEY_LENGTH = 5;

    /**
     * Default length of Activation Code before conversion to Base32.
     * See {@link #generateActivationCode()} method for details.
     */
    private static final int ACTIVATION_CODE_BYTES_LENGTH = 12;

    /**
     * Default length of random bytes used for Activation Code.
     * See {@link #generateActivationCode()} method for details.
     */
    private static final int ACTIVATION_CODE_RANDOM_BYTES_LENGTH = 10;

    private final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Generate a new random activation ID - a UUID level 4 instance.
     *
     * @return New pseudo-random activation ID.
     */
    public String generateActivationId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a new short activation ID. The format of short activation ID is
     * "ABCDE-FGHIJ" - two components, each of them 5 random characters from
     * Base32 encoding, separated by "-" character.
     *
     * @return A new short activation ID.
     */
    public String generateActivationIdShort() {
        return generateBase32Token() + "-" + generateBase32Token();
    }

    /**
     * Generate a new activation OTP. The format of activation OTP is
     * "ABCDE-FGHIJ" - two components, each of them 5 random characters from
     * Base32 encoding, separated by "-" character.
     *
     * @return A new activation OTP.
     */
    public String generateActivationOTP() {
        return generateBase32Token() + "-" + generateBase32Token();
    }

    /**
     * Generate a new string of a default length (5) with characters from Base32 encoding.
     *
     * @return New string with Base32 characters of a given length.
     */
    private String generateBase32Token() {
        byte[] randomBytes = keyGenerator.generateRandomBytes(BASE32_KEY_LENGTH);
        return BaseEncoding.base32().omitPadding().encode(randomBytes).substring(0, BASE32_KEY_LENGTH);
    }

    /**
     * Generate version 3.0 or higher activation code. The format of activation code is "ABCDE-FGHIJ-KLMNO-PQRST".
     *
     * Activation code construction:
     * <ul>
     * <li>Generate 10 random bytes.</li>
     * <li>Calculate CRC-16 from that 10 bytes.</li>
     * <li>Append CRC-16 (2 bytes) in big endian order at the end of random bytes.</li>
     * <li>Generate Base32 representation from these 12 bytes, without padding characters.</li>
     * <li>Split Base32 string into 4 groups, each one contains 5 characters. Use "-" as separator.</li>
     * </ul>
     * @return Generated activation code.
     */
    public String generateActivationCode() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(ACTIVATION_CODE_BYTES_LENGTH);

        // Generate 10 random bytes.
        byte[] randomBytes = keyGenerator.generateRandomBytes(ACTIVATION_CODE_RANDOM_BYTES_LENGTH);
        byteBuffer.put(randomBytes);

        // Calculate CRC-16 from that 10 bytes.
        CRC16 crc16 = new CRC16();
        crc16.update(randomBytes, 0, randomBytes.length);
        long crc = crc16.getValue();

        // Append CRC-16 (2 bytes) in big endian order at the end of random bytes.
        byteBuffer.put((byte) ((crc & 0x0000ff00) >>> 8));
        byteBuffer.put((byte) ((crc & 0x000000ff)));

        // Encode activation code.
        return encodeActivationCode(byteBuffer.array());
    }

    /**
     * Validate activation code using CRC-16 checksum. The expected format of activation code is "ABCDE-FGHIJ-KLMNO-PQRST".
     * @param activationCode Activation code.
     * @return Whether activation code is correct.
     */
    public boolean validateActivationCode(String activationCode) {
        // Validate activation code format
        if (!validateActivationCodeFormat(activationCode)) {
            return false;
        }

        // Decode the Base32 value
        byte[] activationCodeBytes = BaseEncoding.base32().decode(activationCode.replace("-", ""));

        // Split activation code bytes and CRC-16 checksum
        ByteBuffer byteBuffer = ByteBuffer.wrap(activationCodeBytes);
        byte[] activationCodeValue = new byte[10];
        byte[] crc16Bytes = new byte[2];
        byteBuffer.get(activationCodeValue, 0, 10);
        byteBuffer.get(crc16Bytes, 0, 2);

        // Expand actual CRC-16 value by 6 bytes to easily obtain long value
        long actualChecksum = convertCRC16BytesToLong(crc16Bytes);

        // Compute expected checksum
        long expectedChecksum = computeCRC16Checksum(activationCodeValue);

        // Compare checksum values
        return expectedChecksum == actualChecksum;
    }

    /**
     * Extract CRC-16 value from activation codes.
     *
     * @param activationCode Activation code.
     * @return Extracted CRC-16 checksum.
     */
    public long computeChecksum(String activationCode) {
        if (!validateActivationCode(activationCode)) {
            throw new IllegalArgumentException("Invalid activation code: "+activationCode);
        }
        // Decode the Base32 value
        byte[] activationCodeBytes = BaseEncoding.base32().decode(activationCode.replace("-", ""));
        // Extract raw activation code value
        ByteBuffer byteBuffer = ByteBuffer.wrap(activationCodeBytes, 0, 10);
        byte[] activationCodeRaw = new byte[10];
        byteBuffer.get(activationCodeRaw, 0, 10);
        return computeCRC16Checksum(activationCodeRaw);
    }

    /**
     * Compute CRC-16 checksum for given input.
     * @param input Input data in bytes.
     * @return CRC-16 checksum.
     */
    private long computeCRC16Checksum(byte[] input) {
        CRC16 crc16 = new CRC16();
        crc16.update(input, 0, input.length);
        return crc16.getValue();
    }

    /**
     * Validate activation code format.
     * @param activationCode Activation code.
     * @return Whether activation code format is valid.
     */
    private boolean validateActivationCodeFormat(String activationCode) {
        // Verify activation code using regular expression
        if (!activationCode.matches("[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}")) {
            return false;
        }
        // Decode the Base32 value
        byte[] activationCodeBytes = BaseEncoding.base32().decode(activationCode.replace("-", ""));

        // Verify byte array length
        return activationCodeBytes.length == 12;
    }

    /**
     * Convert activation code bytes to Base32 String representation.
     * @param activationCodeBytes Raw activation code bytes.
     * @return Base32 String representation of activation code.
     */
    private String encodeActivationCode(byte[] activationCodeBytes) {
        // Generate Base32 representation from 12 activation code bytes, without padding characters.
        String base32Encoded = BaseEncoding.base32().omitPadding().encode(activationCodeBytes);

        // Split Base32 string into 4 groups, each one contains 5 characters. Use "-" as separator.
        return base32Encoded.substring(0, 5)
                + "-"
                + base32Encoded.substring(5, 10)
                + "-"
                + base32Encoded.substring(10, 15)
                + "-"
                + base32Encoded.substring(15, 20);
    }

    /**
     * Convert two bytes from CRC-16 code to long.
     * @param crc16Bytes CRC-16 bytes.
     * @return The long value.
     */
    private long convertCRC16BytesToLong(byte[] crc16Bytes) {
        // Expand actual CRC-16 value by 6 bytes to easily obtain long value
        ByteBuffer crc16ActualBuffer = ByteBuffer.allocate(Long.BYTES);
        byte[] zeroBytes = new byte[Long.BYTES - 2];
        crc16ActualBuffer.put(zeroBytes);
        crc16ActualBuffer.put(crc16Bytes);
        return Longs.fromByteArray(crc16ActualBuffer.array());
    }
}
