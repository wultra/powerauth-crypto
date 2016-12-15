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

package io.getlime.rest.api.security.controller;

import io.getlime.powerauth.soap.GetActivationStatusResponse;
import io.getlime.powerauth.soap.PrepareActivationResponse;
import io.getlime.powerauth.soap.RemoveActivationResponse;
import io.getlime.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.rest.api.model.request.ActivationCreateRequest;
import io.getlime.rest.api.model.request.ActivationStatusRequest;
import io.getlime.rest.api.model.response.ActivationCreateResponse;
import io.getlime.rest.api.model.response.ActivationRemoveResponse;
import io.getlime.rest.api.model.response.ActivationStatusResponse;
import io.getlime.rest.api.security.application.PowerAuthApplicationConfiguration;
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;
import io.getlime.security.soap.client.PowerAuthServiceClient;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.HeaderParam;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
@Path("pa/activation")
public class ActivationController {

    private final PowerAuthServiceClient powerAuthClient;

    private final PowerAuthAuthenticationProvider authenticationProvider;

    private final PowerAuthApplicationConfiguration applicationConfiguration;

    @Inject
    public ActivationController(PowerAuthServiceClient powerAuthClient, PowerAuthAuthenticationProvider authenticationProvider, PowerAuthApplicationConfiguration applicationConfiguration) {
        this.powerAuthClient = powerAuthClient;
        this.authenticationProvider = authenticationProvider;
        this.applicationConfiguration = applicationConfiguration;
    }

    /**
     * Create a new activation.
     * @param request PowerAuth RESTful request with {@link ActivationCreateRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationCreateResponse} payload.
     */
    @POST
    @Path("create")
    public PowerAuthApiResponse<ActivationCreateResponse> createActivation(PowerAuthApiRequest<ActivationCreateRequest> request) {

        String activationIDShort = request.getRequestObject().getActivationIdShort();
        String activationNonce = request.getRequestObject().getActivationNonce();
        String cDevicePublicKey = request.getRequestObject().getEncryptedDevicePublicKey();
        String activationName = request.getRequestObject().getActivationName();
        String extras = request.getRequestObject().getExtras();
        String applicationKey = request.getRequestObject().getApplicationKey();
        String applicationSignature = request.getRequestObject().getApplicationSignature();
        String clientEphemeralKey = request.getRequestObject().getEphemeralPublicKey();

        PrepareActivationResponse soapResponse = powerAuthClient.prepareActivation(
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

        return new PowerAuthApiResponse<>("OK", response);

    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     */
    @GET
    @Path("status")
    public PowerAuthApiResponse<ActivationStatusResponse> getActivationStatus(PowerAuthApiRequest<ActivationStatusRequest> request) {

        String activationId = request.getRequestObject().getActivationId();

        GetActivationStatusResponse soapResponse = powerAuthClient.getActivationStatus(activationId);

        ActivationStatusResponse response = new ActivationStatusResponse();
        response.setActivationId(soapResponse.getActivationId());
        response.setEncryptedStatusBlob(soapResponse.getEncryptedStatusBlob());
        if (applicationConfiguration != null) {
            response.setCustomObject(applicationConfiguration.statusServiceCustomObject());
        }

        return new PowerAuthApiResponse<>("OK", response);

    }

    /**
     * Get activation status.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param servletRequest Associated servlet request.
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws Exception In case the signature validation fails.
     */
    @POST
    @Path("remove")
    public PowerAuthApiResponse<ActivationRemoveResponse> removeActivation(@HeaderParam(PowerAuthHttpHeader.HEADER_NAME) String signatureHeader, HttpServletRequest servletRequest) throws Exception {

        PowerAuthApiAuthentication apiAuthentication = (PowerAuthApiAuthentication) authenticationProvider.validateRequestSignature("POST", null, "/pa/activation/remove", signatureHeader);

        if (apiAuthentication != null && apiAuthentication.getActivationId() != null) {

            RemoveActivationResponse soapResponse = powerAuthClient.removeActivation(apiAuthentication.getActivationId());

            ActivationRemoveResponse response = new ActivationRemoveResponse();
            response.setActivationId(soapResponse.getActivationId());

            return new PowerAuthApiResponse<>("OK", response);

        } else {

            throw new PowerAuthAuthenticationException("USER_NOT_AUTHENTICATED");

        }
    }

}
