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

import javax.servlet.http.HttpServletRequest;

import io.getlime.banking.soap.client.PowerAuthServiceClient;
import io.getlime.powerauth.soap.VerifySignatureRequest;
import io.getlime.powerauth.soap.VerifySignatureResponse;
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;
import io.getlime.rest.api.security.authentication.PowerAuthAuthentication;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.filter.PowerAuthRequestFilter;
import io.getlime.rest.api.security.http.PowerAuthSignatureHeader;
import io.getlime.rest.api.util.PowerAuthUtil;

@Component
public class PowerAuthAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	private PowerAuthServiceClient powerAuthClient;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		PowerAuthAuthentication powerAuthAuthentication = (PowerAuthAuthentication) authentication;

		VerifySignatureRequest soapRequest = new VerifySignatureRequest();
		soapRequest.setActivationId(powerAuthAuthentication.getActivationId());
		soapRequest.setSignature(powerAuthAuthentication.getSignature());
		soapRequest.setSignatureType(powerAuthAuthentication.getSignatureType());
		try {
			String payload = PowerAuthUtil.getSignatureBaseString(
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

		if (httpAuthorizationHeader == null || httpAuthorizationHeader.equals("undefined")) {
			throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID_EMPTY");
		}

		byte[] requestBodyBytes = ((String)servletRequest.getAttribute(PowerAuthRequestFilter.HTTP_BODY)).getBytes();

		Map<String, String> httpHeaderInfo = PowerAuthUtil.parsePowerAuthSignatureHTTPHeader(httpAuthorizationHeader);
		
		PowerAuthAuthentication powerAuthAuthentication = new PowerAuthAuthentication();
		powerAuthAuthentication.setActivationId(httpHeaderInfo.get(PowerAuthSignatureHeader.ACTIVATION_ID));
		//TODO: here should be the lookup!!!!
		powerAuthAuthentication.setApplicationSecret(httpHeaderInfo.get(PowerAuthSignatureHeader.APPLICATION_ID));
		powerAuthAuthentication.setNonce(httpHeaderInfo.get(PowerAuthSignatureHeader.NONCE));
		powerAuthAuthentication.setSignatureType(httpHeaderInfo.get(PowerAuthSignatureHeader.SIGNATURE_TYPE));
		powerAuthAuthentication.setSignature(httpHeaderInfo.get(PowerAuthSignatureHeader.SIGNATURE));
		powerAuthAuthentication.setHttpMethod(servletRequest.getMethod().toUpperCase());
		powerAuthAuthentication.setRequestUri(requestUriIdentifier);
		powerAuthAuthentication.setData(requestBodyBytes);

		PowerAuthApiAuthentication auth = (PowerAuthApiAuthentication) this.authenticate(powerAuthAuthentication);
		
		if (auth == null) {
			throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID_VALUE");
		}

		return auth;
	}

}
