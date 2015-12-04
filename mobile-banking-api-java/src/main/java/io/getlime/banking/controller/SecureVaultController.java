package io.getlime.banking.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.model.PowerAuthAPIRequest;
import io.getlime.banking.model.PowerAuthAPIResponse;
import io.getlime.banking.model.VaultUnlockRequest;
import io.getlime.banking.model.VaultUnlockResponse;
import io.getlime.banking.soap.client.PowerAuthServiceClient;

@Controller
@RequestMapping(value = "/pa/vault")
public class SecureVaultController {
	
	@Autowired
	private PowerAuthServiceClient powerAuthClient;
	
	@RequestMapping(value = "unlock", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<VaultUnlockResponse> unlockVault(
			@RequestBody PowerAuthAPIRequest<VaultUnlockRequest> request, 
			@RequestHeader(name = "X-PowerAuth-Signature", required = true) String signature) {
		String activationId = request.getRequestObject().getActivationId();
		
		io.getlime.powerauth.soap.VaultUnlockRequest soapRequest = new io.getlime.powerauth.soap.VaultUnlockRequest();
		soapRequest.setActivationId(activationId);
		soapRequest.setSignature(null);
		soapRequest.setSignatureType(null);
		powerAuthClient.unlockVault(soapRequest);
		
		io.getlime.powerauth.soap.VaultUnlockResponse soapResponse = new io.getlime.powerauth.soap.VaultUnlockResponse();
		
		// ... validate the activation information here
		// if (!soapResponse.isSignatureValid()) {
		//    // return error
		// }
		
		VaultUnlockResponse response = new VaultUnlockResponse();
		response.setActivationId(soapResponse.getActivationId());
		response.setcVaultEncryptionKey(soapResponse.getCVaultEncryptionKey());
		
		return new PowerAuthAPIResponse<VaultUnlockResponse>("OK", response);
	}

}
