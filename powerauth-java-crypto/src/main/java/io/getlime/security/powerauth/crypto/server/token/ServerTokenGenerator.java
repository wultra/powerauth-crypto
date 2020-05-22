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
import io.getlime.security.powerauth.crypto.lib.util.TokenUtils;

/**
 * Server side class used for generating new tokens.
 *
 * @author Petr Dvorak, petr@wultra.com
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
     * Generate random token secret, 16 random bytes.
     * @return Random token secret.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    public byte[] generateTokenSecret() throws CryptoProviderException {
        return tokenUtils.generateTokenSecret();
    }

}
