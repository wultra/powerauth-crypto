/*
 * PowerAuth Crypto Library
 * Copyright 2019 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.authentication;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthAuthenticationCodeFormat;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test that validates whether authentication code version to authentication code format works properly.
 */
public class PowerAuthAuthenticationCodeFormatTest {

    @Test
    public void testValidVersions() throws Exception {
        // Transformation from version string.
        assertEquals(PowerAuthAuthenticationCodeFormat.DECIMAL, PowerAuthAuthenticationCodeFormat.getFormatForVersion("3.0"));
        assertEquals(PowerAuthAuthenticationCodeFormat.BASE64, PowerAuthAuthenticationCodeFormat.getFormatForVersion("3.1"));
        assertEquals(PowerAuthAuthenticationCodeFormat.BASE64, PowerAuthAuthenticationCodeFormat.getFormatForVersion("3.2"));
        assertEquals(PowerAuthAuthenticationCodeFormat.BASE64, PowerAuthAuthenticationCodeFormat.getFormatForVersion("3.3"));
        assertEquals(PowerAuthAuthenticationCodeFormat.BASE64, PowerAuthAuthenticationCodeFormat.getFormatForVersion("4.0"));
    }

    @Test
    public void testInvalidV2() {
        assertThrows(GenericCryptoException.class, () ->
            PowerAuthAuthenticationCodeFormat.getFormatForVersion("2.2"));
    }

    @Test
    public void testInvalidV3() {
        assertThrows(GenericCryptoException.class, () ->
            PowerAuthAuthenticationCodeFormat.getFormatForVersion("3.05"));
    }

    @Test
    public void testInvalidFormat1() {
        assertThrows(GenericCryptoException.class, () ->
            PowerAuthAuthenticationCodeFormat.getFormatForVersion("3.1.1"));
    }

    @Test
    public void testInvalidFormat2() {
        assertThrows(GenericCryptoException.class, () ->
            PowerAuthAuthenticationCodeFormat.getFormatForVersion("foo"));
    }

    @Test
    public void testInvalidFormat3() {
        assertThrows(GenericCryptoException.class, () ->
            PowerAuthAuthenticationCodeFormat.getFormatForVersion(""));
    }

    @Test
    public void testInvalidFormat4() {
        assertThrows(GenericCryptoException.class, () ->
            PowerAuthAuthenticationCodeFormat.getFormatForVersion(null));
    }

    @Test
    public void testEnumToStringConversion() {
        // Regular formats
        assertEquals(PowerAuthAuthenticationCodeFormat.DECIMAL, PowerAuthAuthenticationCodeFormat.getEnumFromString("decimal"));
        assertEquals(PowerAuthAuthenticationCodeFormat.DECIMAL, PowerAuthAuthenticationCodeFormat.getEnumFromString("DECIMAL"));
        assertEquals(PowerAuthAuthenticationCodeFormat.BASE64, PowerAuthAuthenticationCodeFormat.getEnumFromString("BASE64"));
        assertEquals(PowerAuthAuthenticationCodeFormat.BASE64, PowerAuthAuthenticationCodeFormat.getEnumFromString("base64"));
        // Invalid formats
        assertNull(PowerAuthAuthenticationCodeFormat.getEnumFromString(""));
        assertNull(PowerAuthAuthenticationCodeFormat.getEnumFromString("foo"));
        assertNull(PowerAuthAuthenticationCodeFormat.getEnumFromString(null));
        // Enum to string conversion
        assertEquals("DECIMAL", PowerAuthAuthenticationCodeFormat.DECIMAL.toString());
        assertEquals("BASE64", PowerAuthAuthenticationCodeFormat.BASE64.toString());
    }
}
