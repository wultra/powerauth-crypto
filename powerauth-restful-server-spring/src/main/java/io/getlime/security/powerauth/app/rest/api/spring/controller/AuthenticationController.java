/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.rest.api.spring.controller;

import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Sample end-point demonstrating how PowerAuth signature validation works.
 *
 * @author Petr Dvorak
 *
 */
@Controller
@RequestMapping(value = "pa/signature")
public class AuthenticationController {

    /**
     * Validate any data sent to this end-point.
     * @return API response with success.
     * @throws Exception In case any error occurs, including during signature validation.
     */
    @RequestMapping(value = "validate", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/signature/validate")
    public @ResponseBody PowerAuthApiResponse<String> login(PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        if (auth != null && auth.getUserId() != null) {
            return new PowerAuthApiResponse<>(PowerAuthApiResponse.Status.OK, "Hooray! User: " + auth.getUserId());
        } else {
            throw new PowerAuthAuthenticationException("Login failed");
        }

    }

}
