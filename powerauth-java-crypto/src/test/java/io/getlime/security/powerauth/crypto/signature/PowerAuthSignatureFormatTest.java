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
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Test that validates whether signature version to signature format works properly.
 */
public class PowerAuthSignatureFormatTest {

    @Test
    public void testValidVersions() throws Exception {
        assertEquals(PowerAuthSignatureFormat.DECIMAL, PowerAuthSignatureFormat.getFormatForSignatureVersion("2.0"));
        assertEquals(PowerAuthSignatureFormat.DECIMAL, PowerAuthSignatureFormat.getFormatForSignatureVersion("2.1"));
        assertEquals(PowerAuthSignatureFormat.DECIMAL, PowerAuthSignatureFormat.getFormatForSignatureVersion("3.0"));
        assertEquals(PowerAuthSignatureFormat.BASE64, PowerAuthSignatureFormat.getFormatForSignatureVersion("3.1"));
        assertEquals(PowerAuthSignatureFormat.BASE64, PowerAuthSignatureFormat.getFormatForSignatureVersion("3.2"));
        assertEquals(PowerAuthSignatureFormat.BASE64, PowerAuthSignatureFormat.getFormatForSignatureVersion("4.0"));
    }

    @Test(expected = GenericCryptoException.class)
    public void testInvalidV2() throws Exception {
        PowerAuthSignatureFormat.getFormatForSignatureVersion("2.2");
    }

    @Test(expected = GenericCryptoException.class)
    public void testInvalidV3() throws Exception {
        PowerAuthSignatureFormat.getFormatForSignatureVersion("3.05");
    }

    @Test(expected = GenericCryptoException.class)
    public void testInvalidFormat1() throws Exception {
        PowerAuthSignatureFormat.getFormatForSignatureVersion("3.1.1");
    }

    @Test(expected = GenericCryptoException.class)
    public void testInvalidFormat2() throws Exception {
        PowerAuthSignatureFormat.getFormatForSignatureVersion("foo");
    }

    @Test(expected = GenericCryptoException.class)
    public void testInvalidFormat3() throws Exception {
        PowerAuthSignatureFormat.getFormatForSignatureVersion("");
    }

    @Test(expected = GenericCryptoException.class)
    public void testInvalidFormat4() throws Exception {
        PowerAuthSignatureFormat.getFormatForSignatureVersion(null);
    }
}
