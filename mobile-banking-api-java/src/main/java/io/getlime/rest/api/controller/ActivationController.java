package io.getlime.rest.api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.soap.client.PowerAuthServiceClient;
import io.getlime.powerauth.soap.GetActivationStatusRequest;
import io.getlime.powerauth.soap.GetActivationStatusResponse;
import io.getlime.powerauth.soap.PrepareActivationRequest;
import io.getlime.powerauth.soap.PrepareActivationResponse;
import io.getlime.powerauth.soap.RemoveActivationRequest;
import io.getlime.powerauth.soap.RemoveActivationResponse;
import io.getlime.rest.api.model.ActivationCreateRequest;
import io.getlime.rest.api.model.ActivationCreateResponse;
import io.getlime.rest.api.model.ActivationRemoveRequest;
import io.getlime.rest.api.model.ActivationRemoveResponse;
import io.getlime.rest.api.model.ActivationStatusRequest;
import io.getlime.rest.api.model.ActivationStatusResponse;
import io.getlime.rest.api.model.PowerAuthAPIRequest;
import io.getlime.rest.api.model.PowerAuthAPIResponse;

@Controller
@RequestMapping(value = "/pa/activation")
public class ActivationController {
	
	@Autowired
	private PowerAuthServiceClient powerAuthClient;

	@RequestMapping(value = "create", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationCreateResponse> createActivation(@RequestBody PowerAuthAPIRequest<ActivationCreateRequest> request) {
		
		String activationIDShort = request.getRequestObject().getActivationIdShort();
		String activationNonce = request.getRequestObject().getActivationNonce();
		String cDevicePublicKey = request.getRequestObject().getcDevicePublicKey();
		String clientName = request.getRequestObject().getClientName();
		
		PrepareActivationRequest soapRequest = new PrepareActivationRequest();
		soapRequest.setActivationIdShort(activationIDShort);
		soapRequest.setActivationNonce(activationNonce);
		soapRequest.setCDevicePublicKey(cDevicePublicKey);
		soapRequest.setClientName(clientName);
		
		PrepareActivationResponse soapResponse = powerAuthClient.prepareActivation(soapRequest);
		
		ActivationCreateResponse response = new ActivationCreateResponse();
		response.setActivationId(soapResponse.getActivationId());
		response.setActivationNonce(soapResponse.getActivationNonce());
		response.setcServerPublicKey(soapResponse.getCServerPublicKey());
		response.setcServerPublicKeySignature(soapResponse.getCServerPublicKeySignature());
		response.setEphemeralPublicKey(soapResponse.getEphemeralPublicKey());
		
		return new PowerAuthAPIResponse<ActivationCreateResponse>("OK", response);
	}
	
	@RequestMapping(value = "status", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationStatusResponse> getActivationStatus(@RequestBody PowerAuthAPIRequest<ActivationStatusRequest> request) {
		String activationId = request.getRequestObject().getActivationId();
		
		GetActivationStatusRequest soapRequest = new GetActivationStatusRequest();
		soapRequest.setActivationId(activationId);
		
		GetActivationStatusResponse soapResponse = powerAuthClient.getActivationStatus(soapRequest);
		
		ActivationStatusResponse response = new ActivationStatusResponse();
		response.setActivationId(soapResponse.getActivationId());
		response.setcStatusBlob(soapResponse.getCStatusBlob());
		
		return new PowerAuthAPIResponse<ActivationStatusResponse>("OK", response);
	}
	
	@RequestMapping(value = "remove", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationRemoveResponse> removeActivation(@RequestBody PowerAuthAPIRequest<ActivationRemoveRequest> request) {
		String activationId = request.getRequestObject().getActivationId();
		
		RemoveActivationRequest soapRequest = new RemoveActivationRequest();
		soapRequest.setActivationId(activationId);
		
		RemoveActivationResponse soapResponse = powerAuthClient.removeActivation(soapRequest);
		
		ActivationRemoveResponse response = new ActivationRemoveResponse();
		response.setActivationId(soapResponse.getActivationId());
		
		return new PowerAuthAPIResponse<ActivationRemoveResponse>("OK", response);
	}
	
}
