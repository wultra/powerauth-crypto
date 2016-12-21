package io.getlime.rest.api.configuration;

import io.getlime.rest.api.security.application.DefaultApplicationConfiguration;
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
