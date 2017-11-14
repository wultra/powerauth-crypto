/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

import io.getlime.security.powerauth.crypto.lib.util.TokenUtils;

/**
 * Class to simplify token verification on the server side.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class ServerTokenVerifier {

    private TokenUtils tokenUtils = new TokenUtils();

    /**
     * Validate provided token digest for given input data and provided token secret.
     * @param nonce Token nonce, 16 random bytes.
     * @param timestamp Token timestamp, Unix timestamp format encoded as 8 bytes.
     * @param tokenSecret Token secret, 16 random bytes.
     * @param tokenDigest Token digest, 32 bytes to be validated.
     * @return Token digest computed using provided data bytes with given token secret.
     */
    public boolean validateTokenDigest(byte[] nonce, byte[] timestamp, byte[] tokenSecret, byte[] tokenDigest) {
        return tokenUtils.validateTokenDigest(nonce, timestamp, tokenSecret, tokenDigest);
    }

}
