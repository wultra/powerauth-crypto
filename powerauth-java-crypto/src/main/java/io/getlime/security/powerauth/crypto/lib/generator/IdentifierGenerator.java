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
import io.getlime.security.powerauth.crypto.lib.util.CRC16;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
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
     */
    private static final int ACTIVATION_CODE_BYTES_LENGTH = 12;

    /**
     * Default length of random bytes used for Activation Code.
     */
    private static final int ACTIVATION_CODE_RANDOM_BYTES_LENGTH = 10;

    /**
     * Secure random to be used for random ID and OTP generator.
     */
    private final SecureRandom secureRandom = new SecureRandom();

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
        return generateBase32Token(secureRandom) + "-" + generateBase32Token(secureRandom);
    }

    /**
     * Generate a new activation OTP. The format of activation OTP is
     * "ABCDE-FGHIJ" - two components, each of them 5 random characters from
     * Base32 encoding, separated by "-" character.
     *
     * @return A new activation OTP.
     */
    public String generateActivationOTP() {
        return generateBase32Token(secureRandom) + "-" + generateBase32Token(secureRandom);
    }

    /**
     * Generate a new string of a default length (5) with characters from Base32 encoding.
     * Because the routines calling this method may call it more than
     * once, an instance of SecureRandom is passed as one of the parameters.
     *
     * @param random An instance of SecureRandom.
     * @return New string with Base32 characters of a given length.
     */
    private String generateBase32Token(SecureRandom random) {
        byte[] randomBytes = new byte[BASE32_KEY_LENGTH];
        random.nextBytes(randomBytes);
        return BaseEncoding.base32().omitPadding().encode(randomBytes).substring(0, BASE32_KEY_LENGTH);
    }

    /**
     * Crypto 3.0 activation code construction:
     * - Generate 10 random bytes.
     * - Calculate CRC-16 from that 10 bytes.
     * - Append CRC-16 in big endian order at the end of random bytes
     * - Generate Base32 representation from that 12 bytes, without padding characters.
     * - Split Base32 string into 4 groups, each one contains 5 characters. Use "-" as separator.
     * @return Generated activation code.
     */
    public String generateActivationCode() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(ACTIVATION_CODE_BYTES_LENGTH);

        // Generate 10 random bytes.
        byte[] randomBytes = new byte[ACTIVATION_CODE_RANDOM_BYTES_LENGTH];
        secureRandom.nextBytes(randomBytes);
        byteBuffer.put(randomBytes);

        // Calculate CRC-16 from that 10 bytes.
        CRC16 crc16 = new CRC16();
        byte[] crc16Value = crc16.compute(randomBytes);

        // Append CRC-16 in big endian order at the end of random bytes
        byteBuffer.put(crc16Value);

        // Generate Base32 representation from that 12 bytes, without padding characters.
        String base32Value = BaseEncoding.base32().omitPadding().encode(byteBuffer.array());

        // Split Base32 string into 4 groups, each one contains 5 characters. Use "-" as separator.
        StringBuilder activationCodeBuilder = new StringBuilder(23);
        for (int i = 0; i < 4; i++) {
            String group = base32Value.substring(i * 5, i * 5 + 5);
            activationCodeBuilder.append(group);
            if (i < 3) {
                activationCodeBuilder.append("-");
            }
        }

        // Return generated activation code.
        return activationCodeBuilder.toString();
    }
}
