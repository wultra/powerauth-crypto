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

package io.getlime.security.powerauth.app.rest.api;

import io.getlime.security.powerauth.app.rest.api.configuration.DefaultJacksonJsonProvider;
import io.getlime.security.powerauth.app.rest.api.controller.AuthenticationController;
import io.getlime.security.powerauth.rest.api.jaxrs.controller.ActivationController;
import io.getlime.security.powerauth.rest.api.jaxrs.controller.SecureVaultController;
import io.getlime.security.powerauth.rest.api.jaxrs.exception.PowerAuthActivationExceptionResolver;
import io.getlime.security.powerauth.rest.api.jaxrs.exception.PowerAuthAuthenticationExceptionResolver;
import io.getlime.security.powerauth.rest.api.jaxrs.exception.PowerAuthSecureVaultExceptionResolver;
import io.getlime.security.powerauth.rest.api.jaxrs.filter.PowerAuthRequestFilter;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.util.HashSet;
import java.util.Set;

/**
 * PowerAuth 2.0 Standard RESTful API application class.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@ApplicationPath("/")
public class JavaEEApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> resources = new HashSet<>();

        // Jackson
        resources.add(DefaultJacksonJsonProvider.class);

        // PowerAuth 2.0 Controllers
        resources.add(AuthenticationController.class);
        resources.add(ActivationController.class);
        resources.add(SecureVaultController.class);

        // PowerAuth 2.0 Exception Resolvers
        resources.add(PowerAuthActivationExceptionResolver.class);
        resources.add(PowerAuthAuthenticationExceptionResolver.class);
        resources.add(PowerAuthSecureVaultExceptionResolver.class);

        // PowerAuth 2.0 Filters
        resources.add(PowerAuthRequestFilter.class);
        return resources;
    }

}
