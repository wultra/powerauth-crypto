/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
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
import io.getlime.rest.api.model.*;
import io.getlime.rest.api.security.application.PowerAuthApplicationConfiguration;
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;
import io.getlime.security.soap.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * @author Petr Dvorak
 *
 */
@Controller
@RequestMapping(value = "/pa/activation")
public class ActivationController {

    @Autowired
    private PowerAuthServiceClient powerAuthClient;

    @Autowired
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Autowired(required = false)
    private PowerAuthApplicationConfiguration applicationConfiguration;

    /**
     * Create a new activation.
     * @param request PowerAuth RESTful request with {@link ActivationCreateRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationCreateResponse} payload.
     */
    @RequestMapping(value = "create", method = RequestMethod.POST)
    public @ResponseBody PowerAuthAPIResponse<ActivationCreateResponse> createActivation(@RequestBody PowerAuthAPIRequest<ActivationCreateRequest> request) {

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

        return new PowerAuthAPIResponse<ActivationCreateResponse>("OK", response);

    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     */
    @RequestMapping(value = "status", method = RequestMethod.POST)
    public @ResponseBody PowerAuthAPIResponse<ActivationStatusResponse> getActivationStatus(@RequestBody PowerAuthAPIRequest<ActivationStatusRequest> request) {

        String activationId = request.getRequestObject().getActivationId();

        GetActivationStatusResponse soapResponse = powerAuthClient.getActivationStatus(activationId);

        ActivationStatusResponse response = new ActivationStatusResponse();
        response.setActivationId(soapResponse.getActivationId());
        response.setEncryptedStatusBlob(soapResponse.getEncryptedStatusBlob());
        if (applicationConfiguration != null) {
            response.setCustomObject(applicationConfiguration.statusServiceCustomObject());
        }

        return new PowerAuthAPIResponse<ActivationStatusResponse>("OK", response);

    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationRemoveRequest} payload.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param servletRequest Associated servlet request.
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws Exception In case the signature validation fails.
     */
    @RequestMapping(value = "remove", method = RequestMethod.POST)
    public @ResponseBody PowerAuthAPIResponse<ActivationRemoveResponse> removeActivation(@RequestBody PowerAuthAPIRequest<ActivationRemoveRequest> request, @RequestHeader(value = PowerAuthHttpHeader.HEADER_NAME, required = true) String signatureHeader, HttpServletRequest servletRequest) throws Exception {

        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", null, "/pa/activation/remove", signatureHeader);

        if (apiAuthentication != null && apiAuthentication.getActivationId() != null) {

            RemoveActivationResponse soapResponse = powerAuthClient.removeActivation(apiAuthentication.getActivationId());

            ActivationRemoveResponse response = new ActivationRemoveResponse();
            response.setActivationId(soapResponse.getActivationId());

            return new PowerAuthAPIResponse<ActivationRemoveResponse>("OK", response);

        } else {

            throw new PowerAuthAuthenticationException("NOT AUTHORIZED");

        }
    }

}
