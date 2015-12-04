package io.getlime.banking.soap.client;

import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

import io.getlime.powerauth.soap.GetActivationStatusRequest;
import io.getlime.powerauth.soap.GetActivationStatusResponse;
import io.getlime.powerauth.soap.PrepareActivationRequest;
import io.getlime.powerauth.soap.PrepareActivationResponse;
import io.getlime.powerauth.soap.RemoveActivationRequest;
import io.getlime.powerauth.soap.RemoveActivationResponse;
import io.getlime.powerauth.soap.VaultUnlockRequest;
import io.getlime.powerauth.soap.VaultUnlockResponse;
import io.getlime.powerauth.soap.VerifySignatureRequest;
import io.getlime.powerauth.soap.VerifySignatureResponse;

public class PowerAuthServiceClient extends WebServiceGatewaySupport {
	
	public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) {
		return (PrepareActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public GetActivationStatusResponse activationStatus(GetActivationStatusRequest request) {
		return (GetActivationStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public RemoveActivationResponse removeActivation(RemoveActivationRequest request) {
		return (RemoveActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public VaultUnlockResponse unlockVault(VaultUnlockRequest request) {
		return (VaultUnlockResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public VerifySignatureResponse verifySignature(VerifySignatureRequest request) {
		return (VerifySignatureResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}

}
