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

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

/**
 * The {@code HashBasedCounterUtils} class provides additional functionality that allows secure transfer
 * and verification of hash based counter over the network.
 */
public class HashBasedCounterUtils {

    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Derivation index used to derive KEY_TRANSPORT_CTR from KEY_TRANSPORT
     */
    private static final long STATUS_BLOB_TRANSPORT_CTR_INDEX = 4000;
    /**
     * Number of bytes allocated for KEY_TRANSPORT_CTR.
     */
    private static final int STATUS_BLOB_TRANSPORT_CTR_LENGTH = 16;
    /**
     * Number of bytes expected for CTR_DATA
     */
    private static final int CTR_DATA_LENGTH = 16;

    /**
     * Calculate hash from value representing the hash based counter. HMAC-SHA256 is currently used as a hashing
     * function.
     *
     * @param ctrData Hash-based counter.
     * @param transportKey Transport key.
     * @return Hash calculated from provided hash-based counter.
     * @throws GenericCryptoException In case that key derivation fails or you provided invalid ctrData.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws InvalidKeyException In case that transport key is not valid.
     */
    public byte[] calculateHashFromHashBasedCounter(byte[] ctrData, SecretKey transportKey)
            throws CryptoProviderException, InvalidKeyException, GenericCryptoException {
        if (ctrData == null || ctrData.length != CTR_DATA_LENGTH) {
            throw new GenericCryptoException("Invalid ctrData provided");
        }
        if (transportKey == null) {
            throw new GenericCryptoException("Invalid transport key");
        }
        // Derive KEY_TRANSPORT_CTR from KEY_TRANSPORT
        final byte[] derivationIndex = ByteBuffer.allocate(STATUS_BLOB_TRANSPORT_CTR_LENGTH)
                .putLong(0L)
                .putLong(STATUS_BLOB_TRANSPORT_CTR_INDEX)
                .array();
        final SecretKey transportCtr = keyGenerator.deriveSecretKey(transportKey, derivationIndex);
        // Derive CTR_DATA_HASH from KEY_TRANSPORT_CTR and CTR_DATA
        final SecretKey ctrDataHashKey = keyGenerator.deriveSecretKeyHmac(transportCtr, ctrData);
        return keyConvertor.convertSharedSecretKeyToBytes(ctrDataHashKey);
    }

    /**
     * Verify whether client's value of hash based counter is equal to the value received from the server. The value
     * received from the server is already hashed, so the function has to calculate hash from the client's counter
     * and then compare both values.
     *
     * @param receivedCtrDataHash Value received from the server, containing hash, calculated from hash based counter.
     * @param expectedCtrData Expected hash based counter.
     * @param transportKey Transport key.
     * @return {@code true} in case that received hash equals to hash calculated from counter data.
     * @throws InvalidKeyException When invalid key is provided.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean verifyHashForHashBasedCounter(byte[] receivedCtrDataHash, byte[] expectedCtrData, SecretKey transportKey)
            throws CryptoProviderException, InvalidKeyException, GenericCryptoException {
        if (expectedCtrData == null || expectedCtrData.length != CTR_DATA_LENGTH) {
            throw new GenericCryptoException("Invalid expected counter data");
        }
        if (receivedCtrDataHash == null || receivedCtrDataHash.length != CTR_DATA_LENGTH) {
            throw new GenericCryptoException("Invalid received counter data hash");
        }
        if (transportKey == null) {
            throw new GenericCryptoException("Invalid transport key");
        }
        // Calculate hash from current hash based counter
        final byte[] expectedCtrDataHash = calculateHashFromHashBasedCounter(expectedCtrData, transportKey);
        // Compare both hashed values
        return SideChannelUtils.constantTimeAreEqual(expectedCtrDataHash, receivedCtrDataHash);
    }
}
