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

package com.wultra.security.powerauth.crypto.lib.encryptor;

import com.wultra.security.powerauth.crypto.lib.encryptor.ecies.ClientEciesEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.ecies.EciesRequestResponseValidator;
import com.wultra.security.powerauth.crypto.lib.encryptor.ecies.ServerEciesEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.*;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;

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
     * @param <Req> The request type, which extends {@link EncryptedRequest}.
     * @param <Res> The response type, which extends {@link EncryptedResponse}.
     * @param encryptorId Identifier of encryptor.
     * @param encryptorParameters Encryptor parameters.
     * @return Client-side encryptor.
     * @throws EncryptorException In case that some required parameter is missing or encryptor cannot be constructed.
     */
    public <Req extends EncryptedRequest, Res extends EncryptedResponse> ClientEncryptor<Req, Res> getClientEncryptor(EncryptorId encryptorId, EncryptorParameters encryptorParameters) throws EncryptorException {
        return getClientEncryptor(encryptorId, encryptorParameters, null);
    }

    /**
     * Create client-side encryptor that can encrypt the request and decrypt the response from the server. In this variant
     * of the function, you can provide {@link EncryptorSecrets} object to properly configure the encryptor to make it
     * ready for the cryptographic tasks.
     *
     * @param <Req> The request type, which extends {@link EncryptedRequest}.
     * @param <Res> The response type, which extends {@link EncryptedResponse}.
     * @param encryptorId Identifier of encryptor.
     * @param encryptorParameters Encryptor parameters.
     * @param encryptorSecrets Optional secrets that will be used to configure the encryptor. If null is provided,
     *                         then you must call {@link ClientEncryptor#configureSecrets(EncryptorSecrets)} later.
     * @return Client-side encryptor.
     * @throws EncryptorException In case that some required parameter is missing or encryptor cannot be constructed or
     *                            configured with the secrets.
     */
    public <Req extends EncryptedRequest, Res extends EncryptedResponse> ClientEncryptor<Req, Res> getClientEncryptor(EncryptorId encryptorId, EncryptorParameters encryptorParameters, EncryptorSecrets encryptorSecrets) throws EncryptorException {
        validateParameters(encryptorId, encryptorParameters);
        switch (encryptorParameters.getProtocolVersion()) {
            case "3.3", "3.2", "3.1", "3.0" -> {
                final ClientEncryptor<EciesEncryptedRequest, EciesEncryptedResponse> encryptor = new ClientEciesEncryptor(encryptorId, encryptorParameters);
                if (encryptorSecrets != null) {
                    encryptor.configureSecrets(encryptorSecrets);
                }
                return (ClientEncryptor<Req, Res>) encryptor;
            }
            default -> {
                throw new EncryptorException("Unsupported protocol version: " + encryptorParameters.getProtocolVersion());
            }
        }
    }

    /**
     * Create server-side encryptor that can decrypt the request from the client and encrypt the response. To use the encryptor
     * properly, you have to call {@link ServerEncryptor#configureSecrets(EncryptorSecrets)} function later on the constructed
     * encryptor to make it ready for the cryptographic tasks.
     *
     * @param <Req> The request type, which extends {@link EncryptedRequest}.
     * @param <Res> The response type, which extends {@link EncryptedResponse}.
     * @param encryptorId Identifier of encryptor.
     * @param encryptorParameters Encryptor parameters.
     * @return Server-side encryptor.
     * @throws EncryptorException In case that some required parameter is missing or encryptor cannot be constructed.
     */
    public <Req extends EncryptedRequest, Res extends EncryptedResponse> ServerEncryptor<Req, Res>  getServerEncryptor(EncryptorId encryptorId, EncryptorParameters encryptorParameters) throws EncryptorException {
        return getServerEncryptor(encryptorId, encryptorParameters, null);
    }

    /**
     * Create server-side encryptor that can decrypt the request from the client and encrypt the response. In this variant
     * of the function, you can provide {@link EncryptorSecrets} object to properly configure the encryptor to make it
     * ready for the cryptographic tasks.
     *
     * @param <Req> The request type, which extends {@link EncryptedRequest}.
     * @param <Res> The response type, which extends {@link EncryptedResponse}.
     * @param encryptorId Identifier of encryptor.
     * @param encryptorParameters Encryptor parameters.
     * @param encryptorSecrets Optional secrets that will be used to configure the encryptor. If null is provided,
     *                         then you must call {@link ServerEncryptor#configureSecrets(EncryptorSecrets)} later.
     * @return Client-side encryptor.
     * @throws EncryptorException In case that some required parameter is missing or encryptor cannot be constructed or
     *                            configured with the secrets.
     */
    public <Req extends EncryptedRequest, Res extends EncryptedResponse> ServerEncryptor<Req, Res> getServerEncryptor(EncryptorId encryptorId, EncryptorParameters encryptorParameters, EncryptorSecrets encryptorSecrets) throws EncryptorException {
        validateParameters(encryptorId, encryptorParameters);
        switch (encryptorParameters.getProtocolVersion()) {
            case "3.3", "3.2", "3.1", "3.0" -> {
                final ServerEncryptor<EciesEncryptedRequest, EciesEncryptedResponse> encryptor = new ServerEciesEncryptor(encryptorId, encryptorParameters);
                if (encryptorSecrets != null) {
                    encryptor.configureSecrets(encryptorSecrets);
                }
                return (ServerEncryptor<Req, Res>) encryptor;
            }
            default -> {
                throw new EncryptorException("Unsupported protocol version: " + encryptorParameters.getProtocolVersion());
            }
        }
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
     *
     * @param <Req> The request type, which extends {@link EncryptedRequest}.
     * @param <Res> The response type, which extends {@link EncryptedResponse}.
     * @param protocolVersion Protocol version.
     * @return Object implementing {@link RequestResponseValidator} interface.
     * @throws EncryptorException In case that protocol is unsupported or not specified.
     */
    public <Req extends EncryptedRequest, Res extends EncryptedResponse> RequestResponseValidator<Req, Res> getRequestResponseValidator(String protocolVersion) throws EncryptorException {
        if (protocolVersion == null) {
            throw new EncryptorException("Missing protocolVersion parameter");
        }
        switch (protocolVersion) {
            case "3.3", "3.2", "3.1", "3.0" -> {
                final RequestResponseValidator<EciesEncryptedRequest, EciesEncryptedResponse> validator = new EciesRequestResponseValidator(protocolVersion);
                return (RequestResponseValidator<Req, Res>) validator;
            }
            default -> {
                throw new EncryptorException("Unsupported protocol version: " + protocolVersion);
            }
        }
    }
}