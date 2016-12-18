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
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthenticationBase;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.api.ServiceLocator;
import org.glassfish.jersey.server.internal.inject.AbstractContainerRequestValueFactory;
import org.glassfish.jersey.server.model.Parameter;
import org.glassfish.jersey.server.spi.internal.ValueFactoryProvider;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthAuthenticationValueProvider implements ValueFactoryProvider {

    @Context
    private HttpServletRequest request;

    @Inject
    private ServiceLocator locator;

    @Override
    public Factory<?> getValueFactory(Parameter parameter) {
        Class<?> classType = parameter.getRawType();
        if (classType != null && PowerAuthApiAuthenticationBase.class.isAssignableFrom(classType)) {
            final Factory<PowerAuthApiAuthentication> factory = new AbstractContainerRequestValueFactory<PowerAuthApiAuthentication>() {

                @Override
                public PowerAuthApiAuthentication provide() {
                    return (PowerAuthApiAuthentication) request.getAttribute(PowerAuth.AUTHENTICATION_OBJECT);
                }

            };
            locator.inject(factory);
            return factory;
        }
        return null;
    }

    @Override
    public PriorityType getPriority() {
        return Priority.NORMAL;
    }

}
