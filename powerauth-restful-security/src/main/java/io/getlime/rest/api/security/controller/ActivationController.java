/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.powerauth.soap.GetActivationStatusResponse;
import io.getlime.powerauth.soap.PrepareActivationResponse;
import io.getlime.powerauth.soap.RemoveActivationResponse;
import io.getlime.rest.api.model.ActivationCreateRequest;
import io.getlime.rest.api.model.ActivationCreateResponse;
import io.getlime.rest.api.model.ActivationRemoveRequest;
import io.getlime.rest.api.model.ActivationRemoveResponse;
import io.getlime.rest.api.model.ActivationStatusRequest;
import io.getlime.rest.api.model.ActivationStatusResponse;
import io.getlime.rest.api.model.PowerAuthAPIRequest;
import io.getlime.rest.api.model.PowerAuthAPIResponse;
import io.getlime.rest.api.security.application.PowerAuthApplicationConfiguration;
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.soap.client.PowerAuthServiceClient;

@Controller
@RequestMapping(value = "/pa/activation")
public class ActivationController {

	@Autowired
	private PowerAuthServiceClient powerAuthClient;

	@Autowired
	private PowerAuthAuthenticationProvider authenticationProvider;
	
	@Autowired
	private PowerAuthApplicationConfiguration applicationConfiguration;

	@RequestMapping(value = "create", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationCreateResponse> createActivation(@RequestBody PowerAuthAPIRequest<ActivationCreateRequest> request) {

		String activationIDShort = request.getRequestObject().getActivationIdShort();
		String activationNonce = request.getRequestObject().getActivationNonce();
		String cDevicePublicKey = request.getRequestObject().getEncryptedDevicePublicKey();
		String activationName = request.getRequestObject().getActivationName();
		String extras = request.getRequestObject().getExtras();
		String applicationKey = request.getRequestObject().getApplicationKey();
		String applicationSignature = request.getRequestObject().getApplicationSignature();
		
		PrepareActivationResponse soapResponse = powerAuthClient.prepareActivation(
				activationIDShort,
				activationName,
				activationNonce,
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

	@RequestMapping(value = "status", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationStatusResponse> getActivationStatus(@RequestBody PowerAuthAPIRequest<ActivationStatusRequest> request) {
		
		String activationId = request.getRequestObject().getActivationId();

		GetActivationStatusResponse soapResponse = powerAuthClient.getActivationStatus(activationId);

		ActivationStatusResponse response = new ActivationStatusResponse();
		response.setActivationId(soapResponse.getActivationId());
		response.setEncryptedStatusBlob(soapResponse.getEncryptedStatusBlob());
		response.setCustomObject(applicationConfiguration.statusServiceCustomObject());

		return new PowerAuthAPIResponse<ActivationStatusResponse>("OK", response);
		
	}

	@RequestMapping(value = "remove", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationRemoveResponse> removeActivation(@RequestBody PowerAuthAPIRequest<ActivationRemoveRequest> request, @RequestHeader(value = "X-PowerAuth-Authorization", required = true) String signatureHeader, HttpServletRequest servletRequest) throws Exception {

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
