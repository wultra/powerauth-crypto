/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.server.token;

import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.TokenUtils;

/**
 * Class to simplify token verification on the server side.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ServerTokenVerifier {

    private final TokenUtils tokenUtils = new TokenUtils();

    /**
     * Helper method to convert provided timestamp into bytes (from string representation), for the
     * purpose of token timestamping.
     *
     * @param timestamp Timestamp to be converted.
     * @return Provided timestamp in milliseconds converted as bytes.
     */
    public byte[] convertTokenTimestamp(long timestamp) {
        return tokenUtils.convertTokenTimestamp(timestamp);
    }

    /**
     * Validate provided token digest for given input data and provided token secret.
     * @param nonce Token nonce, 16 random bytes.
     * @param timestamp Token timestamp, Unix timestamp format encoded as bytes (from string representation).
     * @param version Protocol version.
     * @param tokenSecret Token secret, 16 random bytes.
     * @param tokenDigest Token digest, 32 bytes to be validated.
     * @return Token digest computed using provided data bytes with given token secret.
     * @throws GenericCryptoException In case digest computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean validateTokenDigest(byte[] nonce, byte[] timestamp, String version, byte[] tokenSecret, byte[] tokenDigest) throws GenericCryptoException, CryptoProviderException {
        return tokenUtils.validateTokenDigest(nonce, timestamp, version, tokenSecret, tokenDigest);
    }

}
