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

package io.getlime.rest.api.controller;

import io.getlime.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthenticationBase;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Created by petrdvorak on 18/12/2016.
 */
@Path("pa/signature")
@Produces(MediaType.APPLICATION_JSON)
public class AuthenticationController {

    @Context
    private HttpServletRequest request;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @GET
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    @Path("hello")
    public String hello() {
        return "Hello";
    }

    @POST
    @Path("validate")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.APPLICATION_JSON)
    public PowerAuthApiResponse<String> login(
            String body,
            @HeaderParam(value = PowerAuthHttpHeader.HEADER_NAME) String authHeader
    ) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        PowerAuthApiAuthenticationBase auth = authenticationProvider.validateRequestSignature(
                request,
                "/pa/signature/validate",
                authHeader);

        if (auth != null && auth.getUserId() != null) {
            return new PowerAuthApiResponse<>("OK", "Hooray! User: " + auth.getUserId());
        } else {
            return new PowerAuthApiResponse<>("ERROR", "Authentication failed.");
        }

    }
}
