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
package com.wultra.security.powerauth.crypto.client.authentication;

import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;

import javax.crypto.SecretKey;
import java.util.List;

/**
 * Class implementing client-side authentication related processes.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * For version 4.0 or higher, use the {@link com.wultra.security.powerauth.crypto.lib.util.AuthenticationCodeUtils} directly.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthClientAuthentication {

    private final SignatureUtils signatureUtils = new SignatureUtils();

    /**
     * Compute a PowerAuth authentication code for given data, factor keys and
     * counter. Authentication code keys are symmetric keys deduced using
     * private device key KEY_DEVICE_PRIVATE and server public key
     * KEY_SERVER_PUBLIC, and then using KDF function with proper index. See
     * PowerAuth protocol specification for details.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param data Data to be signed.
     * @param factorKeys Factor keys.
     * @param ctrData Hash based counter / index of the derived key KEY_DERIVED.
     * @param authenticationCodeConfiguration Format and parameters of authentication code to calculate.
     * @return PowerAuth authentication code for given data.
     * @throws GenericCryptoException In case authentication code computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public String authenticateCodeForData(byte[] data, List<SecretKey> factorKeys, byte[] ctrData, AuthenticationCodeConfiguration authenticationCodeConfiguration) throws GenericCryptoException, CryptoProviderException {
        return signatureUtils.computePowerAuthCode(data, factorKeys, ctrData, authenticationCodeConfiguration);
    }

}
