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

package io.getlime.rest.api;

import io.getlime.rest.api.configuration.DefaultJacksonJsonProvider;
import io.getlime.rest.api.controller.AuthenticationController;
import io.getlime.rest.api.security.controller.ActivationController;
import io.getlime.rest.api.security.controller.SecureVaultController;
import io.getlime.rest.api.security.exception.PowerAuthActivationExceptionResolver;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationExceptionResolver;
import io.getlime.rest.api.security.exception.PowerAuthSecureVaultExceptionResolver;
import io.getlime.rest.api.security.filter.PowerAuthRequestFilter;
import org.glassfish.jersey.jackson.JacksonFeature;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
@ApplicationPath("/")
public class JavaEEApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> resources = new HashSet<>();

        // Jackson
        resources.add(JacksonFeature.class);
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

    @Override
    public Map<String, Object> getProperties() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("jersey.config.server.wadl.disableWadl", true);
        return properties;
    }

}
