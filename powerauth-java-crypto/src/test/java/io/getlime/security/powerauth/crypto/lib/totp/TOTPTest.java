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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.TypedArgumentConverter;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.opentest4j.AssertionFailedError;

import java.time.LocalDateTime;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link TOTP}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 *
 */
class TOTPTest {

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testGenerateTOTP(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final String result = switch (algorithm) {
            case "HmacSHA256" -> TOTP.generateTOTPSHA256(fromHex(seed), localDateTime, 8);
            case "HmacSHA512" -> TOTP.generateTOTPSHA512(fromHex(seed), localDateTime, 8);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertEquals(otp, result);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testValidateTOTPCurrentStep(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final boolean result = switch (algorithm) {
            case "HmacSHA256" -> TOTP.validateTOTPSHA256(otp, fromHex(seed), localDateTime);
            case "HmacSHA512" -> TOTP.validateTOTPSHA512(otp, fromHex(seed), localDateTime);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertTrue(result);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testValidateTOTPOneStepBack(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final LocalDateTime movedLocalDateTime = localDateTime.plusSeconds(30);

        final boolean result = switch (algorithm) {
            case "HmacSHA256" -> TOTP.validateTOTPSHA256(otp, fromHex(seed), movedLocalDateTime);
            case "HmacSHA512" -> TOTP.validateTOTPSHA512(otp, fromHex(seed), movedLocalDateTime);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertTrue(result);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testValidateTOTPTwoStepsBack(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final LocalDateTime movedLocalDateTime = localDateTime.plusSeconds(60);

        final boolean result = switch (algorithm) {
            case "HmacSHA256" -> TOTP.validateTOTPSHA256(otp, fromHex(seed), movedLocalDateTime);
            case "HmacSHA512" -> TOTP.validateTOTPSHA512(otp, fromHex(seed), movedLocalDateTime);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertFalse(result);
    }

    private static byte[] fromHex(final String source) {
        return HexFormat.of().parseHex(source);
    }

    static class DateTimeConverter extends TypedArgumentConverter<String, LocalDateTime> {
        protected DateTimeConverter() {
            super(String.class, LocalDateTime.class);
        }

        @Override
        protected LocalDateTime convert(final String source) throws ArgumentConversionException {
            try {
                return LocalDateTime.parse(source);
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to convert", e);
            }
        }
    }
}
