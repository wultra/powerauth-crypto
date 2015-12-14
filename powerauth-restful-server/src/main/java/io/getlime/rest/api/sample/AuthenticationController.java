package io.getlime.rest.api.sample;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
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
@RequestMapping(value = "session")
public class AuthenticationController {

    @Autowired
    private PowerAuthAuthenticationProvider authenticationProvider;

    @RequestMapping(value = "login", method = RequestMethod.POST)
    public @ResponseBody PowerAuthAPIResponse<String> login(
            @RequestHeader(name = "X-PowerAuth-Signature", required = true) String signatureHeader,
            HttpServletRequest servletRequest) throws Exception {

        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.checkRequestSignature(
                servletRequest,
                "/session/login",
                signatureHeader
        );

        if (apiAuthentication != null && apiAuthentication.getUserId() != null) {
            SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
            return new PowerAuthAPIResponse<String>("OK", null);
        } else {
            throw new PowerAuthAuthenticationException("USER_NOT_AUTHENTICATED");
        }

    }

}