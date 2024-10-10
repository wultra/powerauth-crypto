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

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.ClientEciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesRequestResponseValidator;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.ServerEciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;

/**
 * The {@code EncryptorFactory} class provide high level encryptors for PowerAuth End-To-End encryption implementation.
 * You can construct both server and client-side constructors in this factory.
 */
public class EncryptorFactory {
    /**
     * Create client-side encryptor that can encrypt the request and decrypt response from the server. To use the encryptor
     * properly, you have to call {@link ClientEncryptor#configureSecrets(EncryptorSecrets)} function later on the constructed
     * encryptor to make it ready for the cryptographic tasks.
     *
     * @param encryptorId Identifier of encryptor.
     * @param encryptorParameters Encryptor parameters.
     * @return Client-side encryptor.
     * @throws EncryptorException In case that some required parameter is missing or encryptor cannot be constructed.
     */
    public ClientEncryptor getClientEncryptor(EncryptorId encryptorId, EncryptorParameters encryptorParameters) throws EncryptorException {
        return getClientEncryptor(encryptorId, encryptorParameters, null);
    }

    /**
     * Create client-side encryptor that can encrypt the request and decrypt the response from the server. In this variant
     * of the function, you can provide {@link EncryptorSecrets} object to properly configure the encryptor to make it
     * ready for the cryptographic tasks.
     *
     * @param encryptorId Identifier of encryptor.
     * @param encryptorParameters Encryptor parameters.
     * @param encryptorSecrets Optional secrets that will be used to configure the encryptor. If null is provided,
     *                         then you must call {@link ClientEncryptor#configureSecrets(EncryptorSecrets)} later.
     * @return Client-side encryptor.
     * @throws EncryptorException In case that some required parameter is missing or encryptor cannot be constructed or
     *                            configured with the secrets.
     */
    public ClientEncryptor getClientEncryptor(EncryptorId encryptorId, EncryptorParameters encryptorParameters, EncryptorSecrets encryptorSecrets) throws EncryptorException {
        validateParameters(encryptorId, encryptorParameters);
        final ClientEncryptor encryptor;
        switch (encryptorParameters.getProtocolVersion()) {
            case "3.3", "3.2", "3.1", "3.0" -> {
                encryptor = new ClientEciesEncryptor(encryptorId, encryptorParameters);
            }
            default -> {
                throw new EncryptorException("Unsupported protocol version: " + encryptorParameters.getProtocolVersion());
            }
        }
        if (encryptorSecrets != null) {
            encryptor.configureSecrets(encryptorSecrets);
        }
        return encryptor;
    }

    /**
     * Create server-side encryptor that can decrypt the request from the client and encrypt the response. To use the encryptor
     * properly, you have to call {@link ServerEncryptor#configureSecrets(EncryptorSecrets)} function later on the constructed
     * encryptor to make it ready for the cryptographic tasks.
     *
     * @param encryptorId Identifier of encryptor.
     * @param encryptorParameters Encryptor parameters.
     * @return Server-side encryptor.
     * @throws EncryptorException In case that some required parameter is missing or encryptor cannot be constructed.
     */
    public ServerEncryptor getServerEncryptor(EncryptorId encryptorId, EncryptorParameters encryptorParameters) throws EncryptorException {
        return getServerEncryptor(encryptorId, encryptorParameters, null);
    }

    /**
     * Create server-side encryptor that can decrypt the request from the client and encrypt the response. In this variant
     * of the function, you can provide {@link EncryptorSecrets} object to properly configure the encryptor to make it
     * ready for the cryptographic tasks.
     *
     * @param encryptorId Identifier of encryptor.
     * @param encryptorParameters Encryptor parameters.
     * @param encryptorSecrets Optional secrets that will be used to configure the encryptor. If null is provided,
     *                         then you must call {@link ServerEncryptor#configureSecrets(EncryptorSecrets)} later.
     * @return Client-side encryptor.
     * @throws EncryptorException In case that some required parameter is missing or encryptor cannot be constructed or
     *                            configured with the secrets.
     */
    public ServerEncryptor getServerEncryptor(EncryptorId encryptorId, EncryptorParameters encryptorParameters, EncryptorSecrets encryptorSecrets) throws EncryptorException {
        validateParameters(encryptorId, encryptorParameters);
        final ServerEncryptor encryptor;
        switch (encryptorParameters.getProtocolVersion()) {
            case "3.3", "3.2", "3.1", "3.0" -> {
                encryptor = new ServerEciesEncryptor(encryptorId, encryptorParameters);
            }
            default -> {
                throw new EncryptorException("Unsupported protocol version: " + encryptorParameters.getProtocolVersion());
            }
        }
        if (encryptorSecrets != null) {
            encryptor.configureSecrets(encryptorSecrets);
        }
        return encryptor;
    }

    /**
     * Validate input parameters provided to factory function.
     * @param encryptorId Encryptor's identifier.
     * @param parameters Encryptor's parameters.
     * @throws EncryptorException In case that required parameter is missing.
     */
    private static void validateParameters(EncryptorId encryptorId, EncryptorParameters parameters) throws EncryptorException {
        if (encryptorId == null) {
            throw new EncryptorException("Missing encryptorId parameter");
        }
        if (parameters == null) {
            throw new EncryptorException("Missing encryptorParameters parameter");
        }
        if (parameters.getProtocolVersion() == null) {
            throw new EncryptorException("Missing protocolVersion property in encryptorParameters");
        }
        if (parameters.getApplicationKey() == null) {
            throw new EncryptorException("Missing applicationKey property in encryptorParameters");
        }
        if (encryptorId.scope() == EncryptorScope.ACTIVATION_SCOPE && parameters.getActivationIdentifier() == null) {
            throw new EncryptorException("Missing activationIdentifier property in encryptorParameters");
        }
    }

    /**
     * Get request or response data validator for given protocol version.
     * @param protocolVersion Protocol version.
     * @return Object implementing {@link RequestResponseValidator} interface.
     * @throws EncryptorException In case that protocol is unsupported or not specified.
     */
    public RequestResponseValidator getRequestResponseValidator(String protocolVersion) throws EncryptorException {
        if (protocolVersion == null) {
            throw new EncryptorException("Missing protocolVersion parameter");
        }
        switch (protocolVersion) {
            case "3.3", "3.2", "3.1", "3.0" -> {
                return new EciesRequestResponseValidator(protocolVersion);
            }
            default -> {
                throw new EncryptorException("Unsupported protocol version: " + protocolVersion);
            }
        }
    }
}