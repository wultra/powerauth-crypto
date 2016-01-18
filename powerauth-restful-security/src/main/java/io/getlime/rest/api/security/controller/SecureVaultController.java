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

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.rest.api.model.PowerAuthAPIRequest;
import io.getlime.rest.api.model.PowerAuthAPIResponse;
import io.getlime.rest.api.model.VaultUnlockRequest;
import io.getlime.rest.api.model.VaultUnlockResponse;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;
import io.getlime.security.soap.client.PowerAuthServiceClient;

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
		response.setEncryptedVaultEncryptionKey(soapResponse.getEncryptedVaultEncryptionKey());
		
		return new PowerAuthAPIResponse<VaultUnlockResponse>("OK", response);
	}

}
