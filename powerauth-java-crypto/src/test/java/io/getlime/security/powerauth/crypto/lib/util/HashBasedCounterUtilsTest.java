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
package io.getlime.security.powerauth.crypto.lib.util;

import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test verification of hash calculated from the hash based counter.
 */
public class HashBasedCounterUtilsTest {

    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Set up crypto providers
     */
    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testCounterHashCalculationAndVerification()
            throws CryptoProviderException, InvalidKeyException, GenericCryptoException {
        final HashBasedCounterUtils hashBasedCounterUtils = new HashBasedCounterUtils();
        for (int i = 0; i < 100; i++) {
            // Generate random transport key
            final SecretKey transportKey = keyConvertor.convertBytesToSharedSecretKey(keyGenerator.generateRandomBytes(16));
            // Generate random CTR_DATA
            final byte[] ctrData = keyGenerator.generateRandomBytes(16);
            final byte[] ctrDataHashExpected = calculateCtrDataHash(ctrData, transportKey);
            final byte[] ctrDataHashCalculated = hashBasedCounterUtils.calculateHashFromHashBasedCounter(ctrData, transportKey);
            assertArrayEquals(ctrDataHashExpected, ctrDataHashCalculated);
            final boolean ctrDataHashVerified = hashBasedCounterUtils.verifyHashForHashBasedCounter(ctrDataHashCalculated, ctrData, transportKey);
            assertTrue(ctrDataHashVerified);
        }
    }

    /**
     * Helper function that calculates CTR_DATA_HASH from CTR_DATA and KEY_TRANSPORT.
     *
     * @param ctrData Counter data.
     * @param transportKey Transport key.
     * @return Hash calculated from counter data.
     * @throws CryptoProviderException In case that cryptographic provider is not configured properly.
     * @throws InvalidKeyException In case that invalid transport key is provided.
     * @throws GenericCryptoException In case that underlying key generator failed.
     */
    private byte[] calculateCtrDataHash(byte[] ctrData, SecretKey transportKey)
            throws CryptoProviderException, InvalidKeyException, GenericCryptoException {
        final byte[] index = ByteBuffer.allocate(16).putLong(0L).putLong(4000).array();
        final SecretKey ctrInfoKey = keyGenerator.deriveSecretKey(transportKey, index);
        final SecretKey ctrDataHash = keyGenerator.deriveSecretKeyHmac(ctrInfoKey, ctrData);
        return keyConvertor.convertSharedSecretKeyToBytes(ctrDataHash);
    }

}
