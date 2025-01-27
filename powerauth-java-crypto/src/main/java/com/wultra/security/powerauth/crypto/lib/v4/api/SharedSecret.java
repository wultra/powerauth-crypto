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

import com.wultra.security.powerauth.crypto.lib.v4.model.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretAlgorithm;

import javax.crypto.SecretKey;

/**
 * Shared secret interface.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface SharedSecret<SharedSecretRequest, SharedSecretResponse, SharedSecretContext> {

    /**
     * Get algorithm for the shared secret implementation.
     * @return Shared secret algorithm.
     */
    SharedSecretAlgorithm getAlgorithm();

    /**
     * Generate a request cryptogram.
     * @return Request cryptogram.
     */
    RequestCryptogram generateRequestCryptogram() throws Exception;

    /**
     * Generate a response cryptogram.
     * @return Response cryptogram.
     */
    ResponseCryptogram generateResponseCryptogram(SharedSecretRequest request) throws Exception;

    /**
     * Generate a shared secret key.
     * @return Shared secret key.
     */
    SecretKey computeSharedSecret(SharedSecretContext context, SharedSecretResponse response) throws Exception;

}
