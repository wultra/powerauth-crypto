/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.ec;

import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PublicKeyValidator;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for public key validation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PublicKeyValidatorTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Point at infinity test.
     * <p>
     * Infinity is encoded as 0x00 only, it can be imported, but it's an invalid point for a public key.
     */
    @Test
    public void testRejectPointAtInfinity() {
        GenericCryptoException e = assertThrows(GenericCryptoException.class, () -> {
            byte[] pointAtInfinity = new byte[] { 0x00 };
            new KeyConvertor().convertBytesToPublicKey(EcCurve.P256, pointAtInfinity);
        });
        assertEquals("Invalid public key with point equal to the point at infinity", e.getMessage());
    }

    @Test
    public void testUnsupportedCurveWithCofactorGreaterThanOne() {
        GenericCryptoException e = assertThrows(GenericCryptoException.class, () -> {
            var params = CustomNamedCurves.getByName("sect233k1");
            var curve = params.getCurve();
            var point = params.getG();

            new PublicKeyValidator().validate(curve, point);
        });
        assertEquals("Invalid cofactor 4 for curve SecT233K1Curve", e.getMessage());
    }

}
