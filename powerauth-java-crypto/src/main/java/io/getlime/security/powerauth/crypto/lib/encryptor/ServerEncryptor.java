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

import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.*;

/**
 * The {@code ClientEncryptor} interface provides End-To-End Encryption for PowerAuth Clients.
 */
public interface ServerEncryptor {

    /**
     * Get this encryptor's identifier.
     * @return This encryptor's identifier.
     */
    EncryptorParameters getEncryptorParameters();

    /**
     * Get parameters used to construct this encryptor.
     * @return EncryptorParameters used to construct this encryptor.
     */
    EncryptorId getEncryptorId();

    /**
     * Configure secret keys before the encryptor is used for the encryption and decryption tasks.
     * @param secrets Object representing a secret keys for particular protocol version.
     * @throws EncryptorException In case of failure.
     */
    void configureSecrets(EncryptorSecrets secrets) throws EncryptorException;

    /**
     * Determine whether encrypted request data can be decrypted.
     * @return true if response data can be decrypted.
     */
    boolean canDecryptRequest();

    /**
     * Decrypt encrypted request data.
     * @param request Object representing an encrypted request.
     * @return Decrypted data.
     * @throws EncryptorException In case of failure.
     */
    byte[] decryptRequest(EncryptedRequest request) throws EncryptorException;

    /**
     * Determine whether response data can be encrypted. You cannot encrypt the response if you did not
     * decrypt the request before.
     * @return true if response data can be decrypted.
     */
    boolean canEncryptResponse();

    /**
     * Encrypt response data.
     * @param data Data to encrypt as response.
     * @return Object representing an encrypted response.
     * @throws EncryptorException In case of failure.
     */
    EncryptedResponse encryptResponse(byte[] data) throws EncryptorException;
}
