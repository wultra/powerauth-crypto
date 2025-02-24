/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.v4.api;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;

import javax.crypto.SecretKey;

/**
 * Shared secret interface.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface SharedSecret<Req extends SharedSecretRequest, Res extends SharedSecretResponse, Ctx extends SharedSecretClientContext> {

    /**
     * Get algorithm for the shared secret implementation.
     * @return Shared secret algorithm.
     */
    SharedSecretAlgorithm getAlgorithm();

    /**
     * Generate a request cryptogram.
     * @return Request cryptogram.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    RequestCryptogram generateRequestCryptogram() throws GenericCryptoException;

    /**
     * Generate a response cryptogram.
     * @param request Shared secret request.
     * @return Response cryptogram.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    ResponseCryptogram generateResponseCryptogram(Req request) throws GenericCryptoException;

    /**
     * Generate a shared secret key.
     * @param clientContext Client context.
     * @param serverResponse Server response.
     * @return Shared secret key.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    SecretKey computeSharedSecret(Ctx clientContext, Res serverResponse) throws GenericCryptoException;

}
