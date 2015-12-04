package io.getlime.banking.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.model.PowerAuthAPIResponse;
import io.getlime.banking.security.model.ApiAuthentication;
import io.getlime.banking.security.provider.PowerAuthAuthenticationProvider;

@Controller
@RequestMapping(value = "/session")
public class AuthenticationController {
	
	@Autowired
	private PowerAuthAuthenticationProvider authenticationProvider;

	@RequestMapping(value = "login", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<String> login(
			@RequestHeader(name = "X-PowerAuth-Signature", required = true) String signatureHeader,
			HttpServletRequest servletRequest) throws Exception {
		
		ApiAuthentication apiAuthentication = authenticationProvider.checkRequestSignature(
				servletRequest,
				"/session/login", 
				signatureHeader
		);
		
		if (apiAuthentication != null && apiAuthentication.getUserId() != null) {
			SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
			return new PowerAuthAPIResponse<String>("OK", null);
		} else {
			throw new Exception("USER_NOT_AUTHENTICATED");
		}
		
	}
	
}
