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

import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.TypedArgumentConverter;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.opentest4j.AssertionFailedError;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link Totp}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class TotpTest {

    private static final int DIGITS_NUMBER = 8;

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testGenerateTotp(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final Instant instant = localDateTime.toInstant(ZoneOffset.UTC);
        final byte[] result = switch (algorithm) {
            case "HmacSHA256" -> Totp.generateTotpSha256(fromHex(seed), instant, DIGITS_NUMBER);
            case "HmacSHA512" -> Totp.generateTotpSha512(fromHex(seed), instant, DIGITS_NUMBER);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertEquals(otp, new String(result));
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testValidateTotpCurrentStep(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final Instant instant = localDateTime.toInstant(ZoneOffset.UTC);
        final boolean result = switch (algorithm) {
            case "HmacSHA256" -> Totp.validateTotpSha256(otp.getBytes(), fromHex(seed), instant, DIGITS_NUMBER);
            case "HmacSHA512" -> Totp.validateTotpSha512(otp.getBytes(), fromHex(seed), instant, DIGITS_NUMBER);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertTrue(result);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testValidateTotpOneStepBack(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final Instant movedInstant = localDateTime.plusSeconds(30).toInstant(ZoneOffset.UTC);

        final boolean result = switch (algorithm) {
            case "HmacSHA256" -> Totp.validateTotpSha256(otp.getBytes(), fromHex(seed), movedInstant, DIGITS_NUMBER);
            case "HmacSHA512" -> Totp.validateTotpSha512(otp.getBytes(), fromHex(seed), movedInstant, DIGITS_NUMBER);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertTrue(result);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/io/getlime/security/powerauth/crypto/lib/totp/data.csv", useHeadersInDisplayName=true)
    void testValidateTotpTwoStepsBack(final long seconds, final @ConvertWith(DateTimeConverter.class) LocalDateTime localDateTime, final String step, final String otp, final String algorithm, final String seed) throws Exception {
        final Instant movedInstant = localDateTime.plusSeconds(60).toInstant(ZoneOffset.UTC);

        final boolean result = switch (algorithm) {
            case "HmacSHA256" -> Totp.validateTotpSha256(otp.getBytes(), fromHex(seed), movedInstant, DIGITS_NUMBER);
            case "HmacSHA512" -> Totp.validateTotpSha512(otp.getBytes(), fromHex(seed), movedInstant, DIGITS_NUMBER);
            default -> throw new AssertionFailedError("Not supported algorithm " + algorithm);
        };
        assertFalse(result);
    }

    @Test
    void testGenerateTotpLeftPaddedWithZero() throws Exception {
        final Instant instant = parse("2023-04-27T01:26:29Z").toInstant(ZoneOffset.UTC);
        final String result = new String(Totp.generateTotpSha256("12345678901234567890".getBytes(), instant, DIGITS_NUMBER));
        assertEquals("01760428", result);
    }

    @Test
    void testValidateTotpInvalidLength() {
        var exception = Assertions.assertThrows(CryptoProviderException.class, () ->
            Totp.validateTotpSha256("1".getBytes(), "12345678901234567890".getBytes(), Instant.now(), DIGITS_NUMBER));
        assertEquals("Otp length 1 is different from expected 8", exception.getMessage());
    }

    private static byte[] fromHex(final String source) {
        return HexFormat.of().parseHex(source);
    }

    private static LocalDateTime parse(String source) {
        return ZonedDateTime.parse(source, DateTimeFormatter.ISO_DATE_TIME)
                .toLocalDateTime();
    }

    static class DateTimeConverter extends TypedArgumentConverter<String, LocalDateTime> {
        protected DateTimeConverter() {
            super(String.class, LocalDateTime.class);
        }

        @Override
        protected LocalDateTime convert(final String source) throws ArgumentConversionException {
            try {
                return parse(source);
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to convert", e);
            }
        }
    }

}
