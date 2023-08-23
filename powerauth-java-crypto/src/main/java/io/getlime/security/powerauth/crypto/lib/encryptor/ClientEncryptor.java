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
public interface ClientEncryptor {
    /**
     * Get parameters used to construct this encryptor.
     * @return EncryptorParameters used to construct this encryptor.
     */
    EncryptorParameters getEncryptorParameters();

    /**
     * Get this encryptor's identifier.
     * @return This encryptor's identifier.
     */
    EncryptorId getEncryptorId();

    /**
     * Configure secret keys before the encryptor is used for the encryption and decryption tasks.
     * @param secrets Object representing a secret keys for particular protocol version.
     * @throws EncryptorException In case of failure.
     */
    void configureSecrets(EncryptorSecrets secrets) throws EncryptorException;

    /**
     * Determine whether request data can be encrypted.
     * @return true if request data can be encrypted.
     */
    boolean canEncryptRequest();

    /**
     * Encrypt data with this encryptor.
     * @param data Data to encrypt.
     * @return Object representing an encrypted request.
     * @throws EncryptorException In case of failure.
     */
    EncryptedRequest encryptRequest(byte[] data) throws EncryptorException;

    /**
     * Determine whether encrypted response data can be decrypted. You cannot decrypt the response if you did not
     * encrypt the request before.
     * @return true if response data can be decrypted.
     */
    boolean canDecryptResponse();

    /**
     * Decrypt response received from the server.
     * @param response Response data to decrypt.
     * @return decrypted bytes.
     * @throws EncryptorException In case of failure.
     */
    byte[] decryptResponse(EncryptedResponse response) throws EncryptorException;
}
