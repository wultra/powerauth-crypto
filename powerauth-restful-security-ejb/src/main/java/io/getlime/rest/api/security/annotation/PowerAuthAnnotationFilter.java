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

package io.getlime.rest.api.security.annotation;

import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Filter responsible for picking up a PowerAuth annotation and validating the
 * HTTP header value.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class PowerAuthAnnotationFilter implements ContainerRequestFilter {

    @Context
    private ResourceInfo resourceInfo;

    @Context
    private HttpServletRequest request;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {

        Method resourceMethod = resourceInfo.getResourceMethod();
        PowerAuth powerAuthAnnotation = resourceMethod.getAnnotation(PowerAuth.class);

        if (powerAuthAnnotation != null) {
            try {
                PowerAuthApiAuthentication authentication = (PowerAuthApiAuthentication) this.authenticationProvider.validateRequestSignature(
                        request,
                        powerAuthAnnotation.resourceId(),
                        request.getHeader(PowerAuthHttpHeader.HEADER_NAME),
                        new ArrayList<>(Arrays.asList(powerAuthAnnotation.signatureType()))
                );
                request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, authentication);
            } catch (PowerAuthAuthenticationException e) {
                // authentication failed, but we ignore it here and simply do not inject
                // method parameter later, in HandlerMethodArgumentResolver
            }
        }

    }
}
