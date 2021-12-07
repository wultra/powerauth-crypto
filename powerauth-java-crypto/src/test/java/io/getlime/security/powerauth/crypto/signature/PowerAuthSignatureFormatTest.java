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

package io.getlime.security.powerauth.crypto.signature;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test that validates whether signature version to signature format works properly.
 */
public class PowerAuthSignatureFormatTest {

    @Test
    public void testValidVersions() throws Exception {
        // Transformation from version string.
        assertEquals(PowerAuthSignatureFormat.DECIMAL, PowerAuthSignatureFormat.getFormatForSignatureVersion("2.0"));
        assertEquals(PowerAuthSignatureFormat.DECIMAL, PowerAuthSignatureFormat.getFormatForSignatureVersion("2.1"));
        assertEquals(PowerAuthSignatureFormat.DECIMAL, PowerAuthSignatureFormat.getFormatForSignatureVersion("3.0"));
        assertEquals(PowerAuthSignatureFormat.BASE64, PowerAuthSignatureFormat.getFormatForSignatureVersion("3.1"));
        assertEquals(PowerAuthSignatureFormat.BASE64, PowerAuthSignatureFormat.getFormatForSignatureVersion("3.2"));
        assertEquals(PowerAuthSignatureFormat.BASE64, PowerAuthSignatureFormat.getFormatForSignatureVersion("4.0"));
    }

    @Test
    public void testInvalidV2() {
        assertThrows(GenericCryptoException.class, () -> {
            PowerAuthSignatureFormat.getFormatForSignatureVersion("2.2");
        });
    }

    @Test
    public void testInvalidV3() {
        assertThrows(GenericCryptoException.class, () -> {
            PowerAuthSignatureFormat.getFormatForSignatureVersion("3.05");
        });
    }

    @Test
    public void testInvalidFormat1() {
        assertThrows(GenericCryptoException.class, () -> {
            PowerAuthSignatureFormat.getFormatForSignatureVersion("3.1.1");
        });
    }

    @Test
    public void testInvalidFormat2() {
        assertThrows(GenericCryptoException.class, () -> {
            PowerAuthSignatureFormat.getFormatForSignatureVersion("foo");
        });
    }

    @Test
    public void testInvalidFormat3() {
        assertThrows(GenericCryptoException.class, () -> {
            PowerAuthSignatureFormat.getFormatForSignatureVersion("");
        });
    }

    @Test
    public void testInvalidFormat4() {
        assertThrows(GenericCryptoException.class, () -> {
            PowerAuthSignatureFormat.getFormatForSignatureVersion(null);
        });
    }

    @Test
    public void testEnumToStringConversion() {
        // Regular formats
        assertEquals(PowerAuthSignatureFormat.DECIMAL, PowerAuthSignatureFormat.getEnumFromString("decimal"));
        assertEquals(PowerAuthSignatureFormat.DECIMAL, PowerAuthSignatureFormat.getEnumFromString("DECIMAL"));
        assertEquals(PowerAuthSignatureFormat.BASE64, PowerAuthSignatureFormat.getEnumFromString("BASE64"));
        assertEquals(PowerAuthSignatureFormat.BASE64, PowerAuthSignatureFormat.getEnumFromString("base64"));
        // Invalid formats
        assertNull(PowerAuthSignatureFormat.getEnumFromString(""));
        assertNull(PowerAuthSignatureFormat.getEnumFromString("foo"));
        assertNull(PowerAuthSignatureFormat.getEnumFromString(null));
        // Enum to string conversion
        assertEquals("DECIMAL", PowerAuthSignatureFormat.DECIMAL.toString());
        assertEquals("BASE64", PowerAuthSignatureFormat.BASE64.toString());
    }
}
