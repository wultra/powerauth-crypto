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
package com.wultra.security.powerauth.crypto.server.token;

import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.TokenUtils;

/**
 * Server side class used for generating new tokens (V3).
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ServerTokenGenerator {

    private final TokenUtils tokenUtils = new TokenUtils();

    /**
     * Generate random token ID. Use UUID format.
     * @return Random token ID.
     */
    public String generateTokenId() {
        return tokenUtils.generateTokenId();
    }

    /**
     * Generate random 16 byte long token secret.
     * @param version Protocol version.
     * @return Random token secret.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case the protocol version is not supported.
     */
    public byte[] generateTokenSecret(String version) throws CryptoProviderException, GenericCryptoException {
        final byte[] tokenSecret;
        switch (version) {
            case "3.0", "3.1", "3.2", "3.3" -> tokenSecret = tokenUtils.generateTokenSecret(16);
            default -> throw new GenericCryptoException("Unsupported protocol version: " + version);
        }
        return tokenSecret;
    }

}
