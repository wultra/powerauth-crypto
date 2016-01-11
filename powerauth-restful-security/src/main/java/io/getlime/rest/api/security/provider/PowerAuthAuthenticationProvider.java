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
package io.getlime.rest.api.security.provider;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.google.common.io.BaseEncoding;

import javax.servlet.http.HttpServletRequest;

import io.getlime.powerauth.soap.VerifySignatureRequest;
import io.getlime.powerauth.soap.VerifySignatureResponse;
import io.getlime.rest.api.security.application.PowerAuthApplicationConfiguration;
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;
import io.getlime.rest.api.security.authentication.PowerAuthAuthentication;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.filter.PowerAuthRequestFilter;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;
import io.getlime.security.soap.client.PowerAuthServiceClient;

@Component
public class PowerAuthAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	private PowerAuthServiceClient powerAuthClient;
	
	@Autowired
	private PowerAuthApplicationConfiguration applicationConfiguration;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		PowerAuthAuthentication powerAuthAuthentication = (PowerAuthAuthentication) authentication;

		VerifySignatureRequest soapRequest = new VerifySignatureRequest();
		soapRequest.setActivationId(powerAuthAuthentication.getActivationId());
		soapRequest.setSignature(powerAuthAuthentication.getSignature());
		soapRequest.setSignatureType(powerAuthAuthentication.getSignatureType());
		try {
			String payload = PowerAuthHttpBody.getSignatureBaseString(
					powerAuthAuthentication.getHttpMethod(),
					powerAuthAuthentication.getRequestUri(), 
					powerAuthAuthentication.getApplicationSecret(),
					powerAuthAuthentication.getNonce(), 
					powerAuthAuthentication.getData()
			);
			soapRequest.setData(payload);
		} catch (UnsupportedEncodingException | NoSuchAlgorithmException ex) {
			Logger.getLogger(PowerAuthAuthenticationProvider.class.getName()).log(Level.SEVERE, null, ex);
			return null;
		}

		VerifySignatureResponse soapResponse = powerAuthClient.verifySignature(soapRequest);

		if (soapResponse.isSignatureValid()) {
			PowerAuthApiAuthentication apiAuthentication = new PowerAuthApiAuthentication();
			apiAuthentication.setActivationId(soapResponse.getActivationId());
			apiAuthentication.setUserId(soapResponse.getUserId());
			apiAuthentication.setAuthenticated(true);
			return apiAuthentication;
		} else {
			return null;
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		if (authentication == PowerAuthAuthentication.class) {
			return true;
		}
		return false;
	}
	
	public PowerAuthApiAuthentication checkRequestSignature(
			HttpServletRequest servletRequest,
			String requestUriIdentifier,
			String httpAuthorizationHeader) throws Exception {

		// Check for HTTP PowerAuth signature header
		if (httpAuthorizationHeader == null || httpAuthorizationHeader.equals("undefined")) {
			throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID_EMPTY");
		}

		// Get HTTP body bytes
		String requestBodyString = ((String)servletRequest.getAttribute(PowerAuthRequestFilter.HTTP_BODY));
		byte[] requestBodyBytes = requestBodyString == null ? null : BaseEncoding.base64().decode(requestBodyString);

		// Parse HTTP header
		Map<String, String> httpHeaderInfo = PowerAuthHttpHeader.parsePowerAuthSignatureHTTPHeader(httpAuthorizationHeader);
		
		// Fetch application secret, throw exception in case application secret is null
		String applicationId = httpHeaderInfo.get(PowerAuthHttpHeader.APPLICATION_ID);
		String applicationSecret = applicationConfiguration.getApplicationSecretForApplicationId(applicationId);
		if (applicationSecret == null) {
			throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID_APPLICATION_ID");
		}
		
		// Configure PowerAuth authentication object
		PowerAuthAuthentication powerAuthAuthentication = new PowerAuthAuthentication();
		powerAuthAuthentication.setActivationId(httpHeaderInfo.get(PowerAuthHttpHeader.ACTIVATION_ID));
		powerAuthAuthentication.setApplicationSecret(applicationSecret);
		powerAuthAuthentication.setNonce(httpHeaderInfo.get(PowerAuthHttpHeader.NONCE));
		powerAuthAuthentication.setSignatureType(httpHeaderInfo.get(PowerAuthHttpHeader.SIGNATURE_TYPE));
		powerAuthAuthentication.setSignature(httpHeaderInfo.get(PowerAuthHttpHeader.SIGNATURE));
		powerAuthAuthentication.setHttpMethod(servletRequest.getMethod().toUpperCase());
		powerAuthAuthentication.setRequestUri(requestUriIdentifier);
		powerAuthAuthentication.setData(requestBodyBytes);

		// Call the authentication
		PowerAuthApiAuthentication auth = (PowerAuthApiAuthentication) this.authenticate(powerAuthAuthentication);
		
		// In case authentication is null, throw PowerAuth exception
		if (auth == null) {
			throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID_VALUE");
		}

		return auth;
	}

}
