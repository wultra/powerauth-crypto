/*
 * PowerAuth Crypto Library
 * Copyright 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.util;

import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Public key validations which complement validations in Bouncy Castle library.
 */
public class PublicKeyValidator {

    /**
     * Validate the public key:
     * <ul>
     *   <li>check that the EC point is not the point at infinity</li>
     *   <li>check that point order matches the order defined in EC curve</li>
     * </ul>
     *
     * @param curve EC curve.
     * @param point EC point.
     * @throws GenericCryptoException In case the EC point validation fails.
     */
    public void validate(ECCurve curve, ECPoint point) throws GenericCryptoException {
        if (point.isInfinity()) {
            throw new GenericCryptoException("Invalid public key with point equal to the point at infinity");
        }

        final BigInteger n = curve.getOrder();
        final ECPoint calculatedPoint = ECAlgorithms.referenceMultiply(point, n);
        if (!calculatedPoint.isInfinity()) {
            throw new GenericCryptoException("Point order does not match the order defined in EC curve");
        }
    }

}