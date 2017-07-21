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

package io.getlime.security.powerauth.app.rest.api.javaee.controller;

import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Simple demo controller class for signature validation purposes.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Path("pa/signature")
@Produces(MediaType.APPLICATION_JSON)
public class AuthenticationController {

    @Context
    private HttpServletRequest request;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @POST
    @Path("validate")
    @Consumes("*/*")
    @Produces(MediaType.APPLICATION_JSON)
    public ObjectResponse<String> login(String body, @HeaderParam(value = PowerAuthHttpHeader.HEADER_NAME) String authHeader
    ) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        PowerAuthApiAuthentication auth = authenticationProvider.validateRequestSignature(
                request,
                "/pa/signature/validate",
                authHeader
        );

        if (auth != null && auth.getUserId() != null) {
            return new ObjectResponse<>("Hooray! User: " + auth.getUserId());
        } else {
            throw new PowerAuthAuthenticationException("Authentication failed.");
        }

    }

}
