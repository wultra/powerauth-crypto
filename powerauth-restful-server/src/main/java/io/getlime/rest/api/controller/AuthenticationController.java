/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.rest.api.controller;

import io.getlime.rest.api.model.PowerAuthAPIResponse;
import io.getlime.rest.api.security.annotation.PowerAuth;
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;
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
@RequestMapping(value = "/pa/signature")
public class AuthenticationController {

    /**
     * Validate any data sent to this end-point.
     * @param signatureHeader HTTP header with PowerAuth signature.
     * @param servletRequest Servlet request
     * @return API response with success.
     * @throws Exception In case any error occurs, including during signature validation.
     */
    @RequestMapping(value = "validate", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/signature/validate")
    public @ResponseBody PowerAuthAPIResponse<String> login(PowerAuthApiAuthentication apiAuthentication) {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        return new PowerAuthAPIResponse<String>("OK", "Hooray!");

    }

}
