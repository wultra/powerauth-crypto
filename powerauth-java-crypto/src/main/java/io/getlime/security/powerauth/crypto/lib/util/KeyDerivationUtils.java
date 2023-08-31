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
 * The {@code KeyDerivationUtils} class provides additional key derivation functionality defined for PowerAuth protocol.
 */
public class KeyDerivationUtils {

    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Derivation index used to derive KEY_TRANSPORT_IV from KEY_TRANSPORT
     */
    private static final long STATUS_BLOB_TRANSPORT_IV_INDEX = 3000;
    /**
     * Number of bytes allocated for IV.
     */
    private static final int STATUS_BLOB_IV_LENGTH = 16;
    /**
     * Number of bytes expected in challenge parameter.
     */
    private static final int STATUS_BLOB_CHALLENGE_LENGTH = STATUS_BLOB_IV_LENGTH;
    /**
     * Number of bytes expected in nonce parameter.
     */
    private static final int STATUS_BLOB_NONCE_LENGTH = STATUS_BLOB_IV_LENGTH;

    /**
     * Derive Initialization Vector for AES-CBC cipher used for an activation status blob encryption and decryption.
     * The function also supports older protocol versions (V2, V3), where IV was hard-set to array of zero bytes.
     * In this case, both {@code challenge} and {@code nonce} parameters must be {@code null}.
     * <p>
     * <i>Note that non-zero IV was introduced in the protocol version 3.1</i>
     *
     * @param challenge Cryptographic challenge received from the client, or generated in the client.
     * @param nonce Cryptographic nonce received from the server, or generated in the server.
     * @param transportKey Transport key.
     * @return Initialization vector, or zero filled IV when both, {@code challenge} and {@code nonce} parameters are {@code null}.
     * @throws GenericCryptoException In case that key derivation fails or you provided invalid challenge or nonce.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws InvalidKeyException In case that transport key is not valid.
     */
    public byte[] deriveIvForStatusBlobEncryption(byte[] challenge, byte[] nonce, SecretKey transportKey)
            throws GenericCryptoException, CryptoProviderException, InvalidKeyException {
        // In case that challenge and nonce is not provided, then return an empty IV.
        // Non-zero IV is required since the protocol V3.1.
        if (challenge == null && nonce == null) {
            return new byte[STATUS_BLOB_IV_LENGTH];
        }
        // Validate inputs
        if (challenge == null || challenge.length != STATUS_BLOB_CHALLENGE_LENGTH) {
            throw new GenericCryptoException("Invalid challenge provided");
        }
        if (nonce == null || nonce.length != STATUS_BLOB_NONCE_LENGTH) {
            throw new GenericCryptoException("Invalid nonce provided");
        }
        // Derive KEY_TRANSPORT_IV from KEY_TRANSPORT
        final byte[] derivationIndex = ByteBuffer.allocate(STATUS_BLOB_IV_LENGTH)
                .putLong(0L)
                .putLong(STATUS_BLOB_TRANSPORT_IV_INDEX)
                .array();
        final SecretKey transportIv = keyGenerator.deriveSecretKey(transportKey, derivationIndex);
        // Prepare STATUS_IV_DATA as CHALLENGE || NONCE
        final byte[] ivData = ByteUtils.concat(challenge, nonce);
        // Derive IV from KEY_TRANSPORT_IV, CHALLENGE and NONCE
        final SecretKey ivKey = keyGenerator.deriveSecretKeyHmac(transportIv, ivData);
        return keyConvertor.convertSharedSecretKeyToBytes(ivKey);
    }
}
