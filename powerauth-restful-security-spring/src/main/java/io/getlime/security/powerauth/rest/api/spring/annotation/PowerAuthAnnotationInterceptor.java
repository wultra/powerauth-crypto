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

package io.getlime.security.powerauth.rest.api.spring.annotation;

import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;

@Component
public class PowerAuthAnnotationInterceptor extends HandlerInterceptorAdapter {

    private PowerAuthAuthenticationProvider authenticationProvider;

    @Autowired
    public void setAuthenticationProvider(PowerAuthAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        HandlerMethod handlerMethod = (HandlerMethod) handler;
        PowerAuth powerAuthAnnotation = handlerMethod.getMethodAnnotation(PowerAuth.class);

        if (powerAuthAnnotation != null) {

            try {
                PowerAuthApiAuthentication authentication = this.authenticationProvider.validateRequestSignature(
                        request,
                        powerAuthAnnotation.resourceId(),
                        request.getHeader(PowerAuthHttpHeader.HEADER_NAME),
                        new ArrayList<>(Arrays.asList(powerAuthAnnotation.signatureType()))
                );
                if (authentication != null) {
                    request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, authentication);
                }
            } catch (PowerAuthAuthenticationException ex) {
                // silently ignore here and make sure authentication object is null
                request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, null);
            }

        }

        return super.preHandle(request, response, handler);
    }

}
