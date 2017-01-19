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

package io.getlime.security.powerauth.rest.api.jaxrs.controller;

import io.getlime.powerauth.soap.PowerAuthPortServiceStub;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.base.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.request.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.rmi.RemoteException;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
@Path("pa/activation")
@Produces(MediaType.APPLICATION_JSON)
public class ActivationController {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Inject
    private PowerAuthApplicationConfiguration applicationConfiguration;

    /**
     * Create a new activation.
     * @param request PowerAuth RESTful request with {@link ActivationCreateRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationCreateResponse} payload.
     * @throws RemoteException In case SOAP communication fails
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("create")
    public PowerAuthApiResponse<ActivationCreateResponse> createActivation(PowerAuthApiRequest<ActivationCreateRequest> request) throws RemoteException, PowerAuthActivationException {
        try {

            String activationIDShort = request.getRequestObject().getActivationIdShort();
            String activationNonce = request.getRequestObject().getActivationNonce();
            String cDevicePublicKey = request.getRequestObject().getEncryptedDevicePublicKey();
            String activationName = request.getRequestObject().getActivationName();
            String extras = request.getRequestObject().getExtras();
            String applicationKey = request.getRequestObject().getApplicationKey();
            String applicationSignature = request.getRequestObject().getApplicationSignature();
            String clientEphemeralKey = request.getRequestObject().getEphemeralPublicKey();

            PowerAuthPortServiceStub.PrepareActivationResponse soapResponse = powerAuthClient.prepareActivation(
                    activationIDShort,
                    activationName,
                    activationNonce,
                    clientEphemeralKey,
                    cDevicePublicKey,
                    extras,
                    applicationKey,
                    applicationSignature
            );

            ActivationCreateResponse response = new ActivationCreateResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setActivationNonce(soapResponse.getActivationNonce());
            response.setEncryptedServerPublicKey(soapResponse.getEncryptedServerPublicKey());
            response.setEncryptedServerPublicKeySignature(soapResponse.getEncryptedServerPublicKeySignature());
            response.setEphemeralPublicKey(soapResponse.getEphemeralPublicKey());

            return new PowerAuthApiResponse<>(PowerAuthApiResponse.Status.OK, response);

        } catch (Exception e) {
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     * @throws RemoteException In case SOAP communication fails
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("status")
    public PowerAuthApiResponse<ActivationStatusResponse> getActivationStatus(PowerAuthApiRequest<ActivationStatusRequest> request) throws RemoteException, PowerAuthActivationException {
        try {

            String activationId = request.getRequestObject().getActivationId();

            PowerAuthPortServiceStub.GetActivationStatusResponse soapResponse = powerAuthClient.getActivationStatus(activationId);

            ActivationStatusResponse response = new ActivationStatusResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedStatusBlob(soapResponse.getEncryptedStatusBlob());
            if (applicationConfiguration != null) {
                response.setCustomObject(applicationConfiguration.statusServiceCustomObject());
            }

            return new PowerAuthApiResponse<>(PowerAuthApiResponse.Status.OK, response);

        } catch (Exception e) {
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws PowerAuthAuthenticationException In case the signature validation fails.
     * @throws RemoteException In case SOAP communication fails
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("remove")
    public PowerAuthApiResponse<ActivationRemoveResponse> removeActivation(
            @HeaderParam(PowerAuthHttpHeader.HEADER_NAME) String signatureHeader)
            throws PowerAuthAuthenticationException, PowerAuthActivationException {
        try {
            PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", null, "/pa/activation/remove", signatureHeader);

            if (apiAuthentication != null && apiAuthentication.getActivationId() != null) {

                PowerAuthPortServiceStub.RemoveActivationResponse soapResponse = powerAuthClient.removeActivation(apiAuthentication.getActivationId());

                ActivationRemoveResponse response = new ActivationRemoveResponse();
                response.setActivationId(soapResponse.getActivationId());

                return new PowerAuthApiResponse<>(PowerAuthApiResponse.Status.OK, response);

            } else {
                throw new PowerAuthAuthenticationException("USER_NOT_AUTHENTICATED");

            }
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PowerAuthActivationException();
        }
    }


}
