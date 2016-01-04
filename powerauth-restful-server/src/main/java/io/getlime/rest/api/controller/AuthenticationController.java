package io.getlime.rest.api.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.rest.api.model.PowerAuthAPIResponse;
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.provider.PowerAuthAuthenticationProvider;

@Controller
@RequestMapping(value = "/pa/signature")
public class AuthenticationController {

    @Autowired
    private PowerAuthAuthenticationProvider authenticationProvider;

    @RequestMapping(value = "validate", method = RequestMethod.POST)
    public @ResponseBody PowerAuthAPIResponse<String> login(
            @RequestHeader(value = "X-PowerAuth-Authorization", required = true) String signatureHeader,
            HttpServletRequest servletRequest) throws Exception {

        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.checkRequestSignature(
                servletRequest,
                "/pa/signature/validate",
                signatureHeader
        );

        if (apiAuthentication != null && apiAuthentication.getUserId() != null) {
        	// ##EXAMPLE: Here, we could store the authentication in the session like this:
            // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        	return new PowerAuthAPIResponse<String>("OK", "Hooray!");
        } else {
            throw new PowerAuthAuthenticationException("INCORRECT SIGNATURE");
        }

    }

}