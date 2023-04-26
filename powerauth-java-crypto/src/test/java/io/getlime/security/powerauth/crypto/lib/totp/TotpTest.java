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

import org.junit.jupiter.api.Test;
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
 * Test for {@link Totp}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 *
 */
class TotpTest {

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testGenerateTotp(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final String result = switch (algorithm) {
            case "HmacSHA256" -> Totp.generateTotpSha256(fromHex(seed), localDateTime, 8);
            case "HmacSHA512" -> Totp.generateTotpSha512(fromHex(seed), localDateTime, 8);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertEquals(otp, result);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testValidateTotpCurrentStep(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final boolean result = switch (algorithm) {
            case "HmacSHA256" -> Totp.validateTotpSha256(otp, fromHex(seed), localDateTime);
            case "HmacSHA512" -> Totp.validateTotpSha512(otp, fromHex(seed), localDateTime);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertTrue(result);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testValidateTotpOneStepBack(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final LocalDateTime movedLocalDateTime = localDateTime.plusSeconds(30);

        final boolean result = switch (algorithm) {
            case "HmacSHA256" -> Totp.validateTotpSha256(otp, fromHex(seed), movedLocalDateTime);
            case "HmacSHA512" -> Totp.validateTotpSha512(otp, fromHex(seed), movedLocalDateTime);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertTrue(result);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testValidateTotpTwoStepsBack(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final LocalDateTime movedLocalDateTime = localDateTime.plusSeconds(60);

        final boolean result = switch (algorithm) {
            case "HmacSHA256" -> Totp.validateTotpSha256(otp, fromHex(seed), movedLocalDateTime);
            case "HmacSHA512" -> Totp.validateTotpSha512(otp, fromHex(seed), movedLocalDateTime);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertFalse(result);
    }

    @Test
    void testGenerateTotpLeftPaddedWithZero() throws Exception {
        final LocalDateTime localDateTime = LocalDateTime.parse("2023-04-27T01:26:29");
        final String result = Totp.generateTotpSha256("12345678901234567890".getBytes(), localDateTime, 8);
        assertEquals("01760428", result);
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
