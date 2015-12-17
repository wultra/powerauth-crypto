package io.getlime.rest.api.security.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.soap.client.PowerAuthServiceClient;
import io.getlime.rest.api.model.PowerAuthAPIRequest;
import io.getlime.rest.api.model.PowerAuthAPIResponse;
import io.getlime.rest.api.model.VaultUnlockRequest;
import io.getlime.rest.api.model.VaultUnlockResponse;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;

@Controller
@RequestMapping(value = "/pa/vault")
public class SecureVaultController {
	
	@Autowired
	private PowerAuthServiceClient powerAuthClient;
	
	@RequestMapping(value = "unlock", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<VaultUnlockResponse> unlockVault(
			@RequestBody PowerAuthAPIRequest<VaultUnlockRequest> request, 
			@RequestHeader(value = "X-PowerAuth-Authorization", required = true, defaultValue = "unknown") String signatureHeader) throws PowerAuthAuthenticationException {
		
		Map<String, String> map = PowerAuthHttpHeader.parsePowerAuthSignatureHTTPHeader(signatureHeader);
		String activationId = map.get(PowerAuthHttpHeader.ACTIVATION_ID);
		String signature = map.get(PowerAuthHttpHeader.SIGNATURE);
		String signatureType = map.get(PowerAuthHttpHeader.SIGNATURE_TYPE);
		
		io.getlime.powerauth.soap.VaultUnlockResponse soapResponse = powerAuthClient.unlockVault(activationId, signature, signatureType);
		
		if (!soapResponse.isSignatureValid()) {
			throw new PowerAuthAuthenticationException("USER_NOT_AUTHENTICATED");
		}
		
		VaultUnlockResponse response = new VaultUnlockResponse();
		response.setActivationId(soapResponse.getActivationId());
		response.setcVaultEncryptionKey(soapResponse.getCVaultEncryptionKey());
		
		return new PowerAuthAPIResponse<VaultUnlockResponse>("OK", response);
	}

}
