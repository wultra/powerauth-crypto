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
package com.wultra.security.powerauth.crypto.lib.generator;

import com.wultra.security.powerauth.crypto.lib.encryptor.ecies.kdf.KdfX9_63;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.CRC16;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import org.bouncycastle.util.encoders.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Generator of identifiers used in PowerAuth protocol.
 *
 * @author Petr Dvorak, petr.dvorak@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class IdentifierGenerator {

    private static final Logger logger = LoggerFactory.getLogger(IdentifierGenerator.class);

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

    /**
     * Maximum number of attempts for PUK derivation.
     */
    private static final int PUK_DERIVATION_MAX_ATTEMPTS = 20;

    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Generate a new random activation ID - a UUID level 4 instance.
     *
     * @return New pseudo-random activation ID.
     */
    public String generateActivationId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate version 3.0 or higher activation code. The format of activation code is "ABCDE-FGHIJ-KLMNO-PQRST".
     * <p>
     * Activation code construction:
     * <ul>
     * <li>Generate 10 random bytes.</li>
     * <li>Calculate CRC-16 from that 10 bytes.</li>
     * <li>Append CRC-16 (2 bytes) in big endian order at the end of random bytes.</li>
     * <li>Generate Base32 representation from these 12 bytes, without padding characters.</li>
     * <li>Split Base32 string into 4 groups, each one contains 5 characters. Use "-" as separator.</li>
     * </ul>
     *
     * @return Generated activation code.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    public String generateActivationCode() throws CryptoProviderException {
        try {
            // Generate 10 random bytes.
            byte[] randomBytes = keyGenerator.generateRandomBytes(ACTIVATION_CODE_RANDOM_BYTES_LENGTH);
            return generateActivationCode(randomBytes);
        } catch (GenericCryptoException ex) {
            logger.warn(ex.getMessage(), ex);
            // Exception cannot occur, the random code length is specified correctly
            return null;
        }
    }

    /**
     * Generate version 3.0 or higher activation code using provided random bytes. The format of activation code
     * is "ABCDE-FGHIJ-KLMNO-PQRST".
     * <p>
     * Activation code construction:
     * <ul>
     * <li>Use provided 10 random bytes.</li>
     * <li>Calculate CRC-16 from that 10 bytes.</li>
     * <li>Append CRC-16 (2 bytes) in big endian order at the end of random bytes.</li>
     * <li>Generate Base32 representation from these 12 bytes, without padding characters.</li>
     * <li>Split Base32 string into 4 groups, each one contains 5 characters. Use "-" as separator.</li>
     * </ul>
     *
     * @param randomBytes Random bytes to use when generating the activation code.
     * @return Generated activation code.
     * @throws GenericCryptoException In case generating activation code fails.
     */
    public String generateActivationCode(byte[] randomBytes) throws GenericCryptoException {
        if (randomBytes == null || randomBytes.length != ACTIVATION_CODE_RANDOM_BYTES_LENGTH) {
            throw new GenericCryptoException("Invalid request in generateActivationCode");
        }
        ByteBuffer byteBuffer = ByteBuffer.allocate(ACTIVATION_CODE_BYTES_LENGTH);
        byteBuffer.put(randomBytes);

        // Calculate CRC-16 from that 10 bytes.
        CRC16 crc16 = new CRC16();
        crc16.update(randomBytes, 0, ACTIVATION_CODE_RANDOM_BYTES_LENGTH);
        long crc = crc16.getValue();

        // Append CRC-16 (2 bytes) in big endian order at the end of random bytes.
        byteBuffer.putShort((short) crc);

        // Encode activation code.
        return encodeActivationCode(byteBuffer.array());
    }

    /**
     * Validate activation code using CRC-16 checksum. The expected format of activation code is "ABCDE-FGHIJ-KLMNO-PQRST".
     *
     * @param activationCode Activation code.
     * @return Whether activation code is correct.
     */
    public boolean validateActivationCode(String activationCode) {
        if (activationCode == null) {
            return false;
        }
        String partRegexp = "[A-Z2-7]{" + BASE32_KEY_LENGTH + "}";
        String activationCodeRegexp = partRegexp + "-" + partRegexp + "-" + partRegexp + "-" + partRegexp;
        // Verify activation code using regular expression
        if (!activationCode.matches(activationCodeRegexp)) {
            return false;
        }

        final String activationCodeBase32 = fetchActivationCodeBase32(activationCode);
        final byte[] activationCodeBytes = Base32.decode(activationCodeBase32);

        // Verify byte array length
        if (activationCodeBytes.length != ACTIVATION_CODE_BYTES_LENGTH) {
            return false;
        }

        // Compute checksum from first 10 bytes
        CRC16 crc16 = new CRC16();
        crc16.update(activationCodeBytes, 0, ACTIVATION_CODE_RANDOM_BYTES_LENGTH);
        long actualChecksum = crc16.getValue();

        // Convert the two CRC-16 bytes to long, see Longs.fromByteArray()
        long expectedChecksum = ((long) activationCodeBytes[ACTIVATION_CODE_BYTES_LENGTH - 2] & 255L) << 8 | (long) activationCodeBytes[ACTIVATION_CODE_BYTES_LENGTH - 1] & 255L;

        // Compare checksum values
        return expectedChecksum == actualChecksum;
    }

    /**
     * Remove hyphens and calculate padding.
     * <p>
     * When {@code ACTIVATION_CODE_BYTES_LENGTH = 12}, the Base32 padding is always {@code ====}, but this method is safe to change the length in the future.
     *
     * @param activationCode activation code with hyphens
     * @return base32 with padding
     */
    private static String fetchActivationCodeBase32(final String activationCode) {
        final String activationCodeWithoutHyphens = activationCode.replace("-", "");
        // The activation code does not contain the padding, but it must be present in the Base32 value to be valid.
        final String activationCodePadding = switch (activationCodeWithoutHyphens.length() % 8) {
            case 2:
                yield "======";
            case 4:
                yield "====";
            case 5:
                yield "===";
            case 7:
                yield "=";
            default:
                yield "";
        };
        return activationCodeWithoutHyphens + activationCodePadding;
    }

    /**
     * Convert activation code bytes to Base32 String representation.
     *
     * @param activationCodeBytes Raw activation code bytes.
     * @return Base32 String representation of activation code.
     */
    private String encodeActivationCode(final byte[] activationCodeBytes) {
        // Padding may be ignored; ACTIVATION_CODE_BYTES_LENGTH is set to 12 and the following substring takes only the first 20 characters.
        final String base32Encoded = Base32.toBase32String(activationCodeBytes);

        // Split Base32 string into 4 groups, each one contains 5 characters. Use "-" as separator.
        return base32Encoded.substring(0, BASE32_KEY_LENGTH)
                + "-"
                + base32Encoded.substring(BASE32_KEY_LENGTH, BASE32_KEY_LENGTH * 2)
                + "-"
                + base32Encoded.substring(BASE32_KEY_LENGTH * 2, BASE32_KEY_LENGTH * 3)
                + "-"
                + base32Encoded.substring(BASE32_KEY_LENGTH * 3, BASE32_KEY_LENGTH * 4);
    }

}
