/*
 * PowerAuth Crypto Library
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.crypto.lib.encryptor;

import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;

/**
 * The {@code RequestResponseValidator} interface allows you to formally validate the encrypted request or response data
 * in advance, before you try to decrypt it.
 */
public interface RequestResponseValidator {
    /**
     * Test whether encrypted request contains valid data. The function does a simple formal validation whether
     * all required parameters are present in the request object.
     *
     * @param request Encrypted request object to validate.
     * @return true if object appears to contain valid data, otherwise false.
     */
    boolean validateEncryptedRequest(EncryptedRequest request);

    /**
     * Test whether encrypted response contains valid data. The function does a simple formal validation whether
     * all required parameters are present in the response object.
     *
     * @param response Encrypted response object to validate.
     * @return true if object appears to contain valid data, otherwise false.
     */
    boolean validateEncryptedResponse(EncryptedResponse response);
}
