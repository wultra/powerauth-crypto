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

package io.getlime.security.powerauth.app.rest.api.javaee.controller;

import io.getlime.powerauth.soap.PowerAuthPortServiceStub;
import io.getlime.security.powerauth.rest.api.model.request.ActivationCreateCustomRequest;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthNonPersonalizedEncryptor;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.provider.PowerAuthUserProvider;
import io.getlime.security.powerauth.rest.api.jaxrs.encryption.EncryptorFactory;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.model.request.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationCreateResponse;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Path("pa/custom/activation")
@Produces(MediaType.APPLICATION_JSON)
public class CustomActivationController {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    @Inject
    private EncryptorFactory encryptorFactory;

    @Inject
    private PowerAuthUserProvider userProvider;

    @POST
    @Path("create")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> createNewActivation(PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> object) throws PowerAuthAuthenticationException, RemoteException, PowerAuthActivationException {
        try {

            final PowerAuthNonPersonalizedEncryptor encryptor = encryptorFactory.buildNonPersonalizedEncryptor(object);

            if (encryptor == null) {
                throw new PowerAuthActivationException();
            }

            ActivationCreateCustomRequest request = encryptor.decrypt(object, ActivationCreateCustomRequest.class);

            if (request == null) {
                throw new PowerAuthActivationException();
            }

            final Map<String, String> identity = request.getIdentity();
            String userId = userProvider.lookupUserIdForAttributes(identity);

            if (userId == null) {
                throw new PowerAuthActivationException();
            }

            ActivationCreateRequest acr = request.getPowerauth();
            PowerAuthPortServiceStub.CreateActivationResponse response = powerAuthClient.createActivation(
                    acr.getApplicationKey(),
                    userId,
                    acr.getActivationIdShort(),
                    acr.getActivationName(),
                    acr.getActivationNonce(),
                    acr.getEphemeralPublicKey(),
                    acr.getEncryptedDevicePublicKey(),
                    acr.getExtras(),
                    acr.getApplicationSignature()
            );

            final Map<String, Object> customAttributes = request.getCustomAttributes();
            userProvider.processCustomActivationAttributes(customAttributes);

            ActivationCreateResponse createResponse = new ActivationCreateResponse();
            createResponse.setActivationId(response.getActivationId());
            createResponse.setEphemeralPublicKey(response.getEphemeralPublicKey());
            createResponse.setActivationNonce(response.getActivationNonce());
            createResponse.setEncryptedServerPublicKey(response.getEncryptedServerPublicKey());
            createResponse.setEncryptedServerPublicKeySignature(response.getEncryptedServerPublicKeySignature());

            final PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> powerAuthApiResponse = encryptor.encrypt(createResponse);

            if (userProvider.shouldAutoCommitActivation(identity, customAttributes)) {
                powerAuthClient.commitActivation(response.getActivationId());
            }

            return powerAuthApiResponse;

        } catch (IOException e) {
            throw new PowerAuthActivationException();
        }

    }

}
