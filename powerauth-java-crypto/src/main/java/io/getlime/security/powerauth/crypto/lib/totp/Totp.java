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
package io.getlime.security.powerauth.crypto.lib.totp;

import com.google.common.base.Strings;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;

/**
 * TOTP: Time-Based One-Time Password Algorithm according to <a href="https://www.rfc-editor.org/rfc/rfc6238">RFC 6238</a>.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
public final class Totp {

    private static final Logger logger = LoggerFactory.getLogger(Totp.class);

    /**
     * Default time-step size of 30 seconds recommended by RFC. The value is selected as a balance between security and usability.
     */
    private static final int TIME_STEP_X = 30;

    private Totp() {
        throw new IllegalStateException("Should not be instantiated");
    }

    private static final int[] DIGITS_POWER
            // 0  1   2    3      4       5        6          7           8
            = {1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000};

    /**
     * Generates a TOTP value for the given set of parameters using HmacSHA256 algorithm.
     *
     * @param key           the shared secret
     * @param localDateTime date time
     * @param returnDigits  number of digits to return
     * @return a numeric String in base 10 that includes truncation digits
     * @throws CryptoProviderException in case of any crypto error
     */
    public static String generateTotpSha256(final byte[] key, final LocalDateTime localDateTime, final int returnDigits) throws CryptoProviderException {
        return generateTotp(key, countTimeSteps(localDateTime), returnDigits, Algorithm.HMAC_SHA256.code);
    }

    /**
     * Generates a TOTP value for the given set of parameters using HmacSHA512 algorithm.
     *
     * @param key           the shared secret
     * @param localDateTime date time
     * @param returnDigits  number of digits to return
     * @return a numeric String in base 10 that includes truncation digits
     * @throws CryptoProviderException in case of any crypto error
     */
    public static String generateTotpSha512(final byte[] key, final LocalDateTime localDateTime, final int returnDigits) throws CryptoProviderException {
        return generateTotp(key, countTimeSteps(localDateTime), returnDigits, Algorithm.HMAC_SHA512.code);
    }

    /**
     * Validate a TOTP value for the given set of parameters using HmacSHA256 algorithm. Validates one time step backward.
     *
     * @param otp           TOTP to validate
     * @param key           the shared secret
     * @param localDateTime date time
     * @return true if OTP is valid
     * @throws CryptoProviderException in case of any crypto error
     * @see #validateTotpSha256(String, byte[], LocalDateTime, int)
     */
    public static boolean validateTotpSha256(final String otp, final byte[] key, final LocalDateTime localDateTime) throws CryptoProviderException {
        return validateTotpSha256(otp, key, localDateTime, 1);
    }

    /**
     * Validate a TOTP value for the given set of parameters using HmacSHA256 algorithm.
     *
     * @param otp           TOTP to validate
     * @param key           the shared secret
     * @param localDateTime date time
     * @param steps         number of backward time steps allowed to validate
     * @return true if OTP is valid
     * @throws CryptoProviderException in case of any crypto error
     */
    public static boolean validateTotpSha256(final String otp, final byte[] key, final LocalDateTime localDateTime, final int steps) throws CryptoProviderException {
        return validateTotp(otp, key, localDateTime, steps, Algorithm.HMAC_SHA256.code);
    }

    /**
     * Validate a TOTP value for the given set of parameters using HmacSHA512 algorithm. Validates one time step backward.
     *
     * @param otp           TOTP to validate
     * @param key           the shared secret
     * @param localDateTime date time
     * @return true if OTP is valid
     * @throws CryptoProviderException in case of any crypto error
     * @see #validateTotpSha512(String, byte[], LocalDateTime, int)
     */
    public static boolean validateTotpSha512(final String otp, final byte[] key, final LocalDateTime localDateTime) throws CryptoProviderException {
        return validateTotpSha512(otp, key, localDateTime, 1);
    }

    /**
     * Validate a TOTP value for the given set of parameters using HmacSHA512 algorithm.
     *
     * @param otp           TOTP to validate
     * @param key           the shared secret
     * @param localDateTime date time
     * @param steps         number of backward time steps allowed to validate
     * @return true if OTP is valid
     * @throws CryptoProviderException in case of any crypto error
     */
    public static boolean validateTotpSha512(final String otp, final byte[] key, final LocalDateTime localDateTime, final int steps) throws CryptoProviderException {
        return validateTotp(otp, key, localDateTime, steps, Algorithm.HMAC_SHA512.code);
    }

    /**
     * Validate a TOTP value for the given set of parameters.
     *
     * @param otp           TOTP to validate
     * @param key           the shared secret
     * @param localDateTime date time
     * @param backwardSteps number of backward time steps allowed to validate
     * @param algorithm     the algorithm to use
     * @return true if OTP is valid
     * @throws CryptoProviderException in case of any crypto error
     */
    private static boolean validateTotp(final String otp, final byte[] key, final LocalDateTime localDateTime, final int backwardSteps, final String algorithm) throws CryptoProviderException {
        logger.debug("Validating TOTP for localDateTime={}, algorithm={}, steps={}", localDateTime, algorithm, backwardSteps);

        if (otp == null || otp.trim().length() == 0) {
            throw new CryptoProviderException("Otp is mandatory");
        }

        if (backwardSteps < 0) {
            throw new CryptoProviderException("Steps must not be negative number");
        }

        long currentTimeStep = countTimeSteps(localDateTime);
        for (int i = 0; i <= backwardSteps; i++) {
            logger.debug("Validating TOTP for localDateTime={}, algorithm={}, step={} out of allowed backward steps={}", localDateTime, algorithm, i, backwardSteps);
            final long step = currentTimeStep - i;
            final String expectedOtp = generateTotp(key, step, otp.length(), algorithm);
            if (Arrays.constantTimeAreEqual(expectedOtp.getBytes(), otp.getBytes())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generates a TOTP value for the given set of parameters.
     *
     * @param key          the shared secret
     * @param timeStep     number of time step
     * @param returnDigits number of digits to return
     * @param algorithm    the algorithm to use
     * @return a numeric String in base 10 that includes truncation digits
     * @throws CryptoProviderException in case of any crypto error
     */
    private static String generateTotp(final byte[] key, final long timeStep, final int returnDigits, final String algorithm) throws CryptoProviderException {
        logger.debug("Generating TOTP for timeStep={}, algorithm={}", timeStep, algorithm);

        if (key == null) {
            throw new CryptoProviderException("Key is mandatory");
        }

        if (algorithm == null) {
            throw new CryptoProviderException("Algorithm is mandatory");
        }

        if (returnDigits <= 0 || returnDigits >= DIGITS_POWER.length) {
            throw new CryptoProviderException("ReturnDigits must be positive number and smaller than " + DIGITS_POWER.length);
        }

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC4226 (HOTP)
        final String timeWithCounterPrefix = padWithZeros(Long.toHexString(timeStep), 16);

        // Get the HEX in a byte[]
        final byte[] msg = HexFormat.of().parseHex(timeWithCounterPrefix);

        final byte[] hash = computeHash(algorithm, key, msg);

        // put selected bytes into result int
        final int offset = hash[hash.length - 1] & 0xf;

        final int binary = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        final int otp = binary % DIGITS_POWER[returnDigits];

        final String result = Integer.toString(otp);
        return padWithZeros(result, returnDigits);
    }

    private static long countTimeSteps(final LocalDateTime localDateTime) throws CryptoProviderException {
        if (localDateTime == null) {
            throw new CryptoProviderException("LocalDateTime is mandatory");
        }

        return localDateTime.toEpochSecond(ZoneOffset.UTC) / TIME_STEP_X;
    }

    private static String padWithZeros(final String source, final int length) {
        return Strings.padStart(source, length, '0');
    }

    /**
     * Computes a Hashed Message Authentication Code with the give hash algorithm as a parameter.
     *
     * @param algorithm the algorithm
     * @param keyBytes  the bytes to use for the HMAC key
     * @param data      data to be hashed
     * @throws CryptoProviderException in case of any crypto error
     */
    @SuppressWarnings("java:S2139") // NOSONAR we need to be sure that the exception is logged, better twice than never
    private static byte[] computeHash(final String algorithm, final byte[] keyBytes, final byte[] data) throws CryptoProviderException {
        try {
            final Mac hmac = Mac.getInstance(algorithm);
            final SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(data);
        } catch (GeneralSecurityException e) {
            logger.error("Problem to compute hash for algorithm={}", algorithm, e);
            throw new CryptoProviderException("Problem to compute hash for algorithm=" + algorithm, e);
        }
    }

    private enum Algorithm {
        HMAC_SHA256("HmacSHA256"),
        HMAC_SHA512("HmacSHA512");

        private final String code;

        Algorithm(String code) {
            this.code = code;
        }
    }
}
