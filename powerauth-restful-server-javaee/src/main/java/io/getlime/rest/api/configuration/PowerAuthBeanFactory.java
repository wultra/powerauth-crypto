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

package io.getlime.rest.api.configuration;

import io.getlime.rest.jaxrs.api.security.application.DefaultApplicationConfiguration;
import io.getlime.rest.api.security.application.PowerAuthApplicationConfiguration;
import io.getlime.security.soap.axis.client.PowerAuthServiceClient;
import org.apache.axis2.AxisFault;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;

/**
 * Class responsible for bean auto-wiring.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Dependent
public class PowerAuthBeanFactory {

    @Produces
    public PowerAuthServiceClient buildClient() {
        try {
            return new PowerAuthServiceClient("http://localhost:8080/powerauth-java-server/soap");
        } catch (AxisFault axisFault) {
            return null;
        }
    }

    @Produces
    public PowerAuthApplicationConfiguration buildApplicationConfiguration() {
        return new DefaultApplicationConfiguration();
    }

}
