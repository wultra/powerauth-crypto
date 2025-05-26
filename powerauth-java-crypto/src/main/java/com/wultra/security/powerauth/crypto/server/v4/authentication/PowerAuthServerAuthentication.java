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
package com.wultra.security.powerauth.crypto.server.v4.authentication;

import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AuthenticationCodeUtils;

import javax.crypto.SecretKey;
import java.util.List;

/**
 * Class implementing processes PowerAuth Server uses to compute and validate
 * authentication codes (V4).
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthServerAuthentication {

    private final AuthenticationCodeUtils authenticationCodeUtils = new AuthenticationCodeUtils();

    /**
     * Verify the authentication code against data using authentication code key list and
     * counter.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param data Signed data.
     * @param authenticationCode Authentication code for the data.
     * @param factorKeys Keys used for verification.
     * @param ctrData Hash based counter / derived signing key index.
     * @param authenticationCodeConfiguration Format and parameters of authentication code to verify.
     * @return Returns "true" if the authentication code matches, "false" otherwise.
     * @throws GenericCryptoException In case authentication code computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean validateAuthCode(byte[] data, String authenticationCode, List<SecretKey> factorKeys, byte[] ctrData, AuthenticationCodeConfiguration authenticationCodeConfiguration) throws GenericCryptoException, CryptoProviderException {
        return authenticationCodeUtils.validateAuthCode(data, authenticationCode, factorKeys, ctrData, authenticationCodeConfiguration);
    }

}
