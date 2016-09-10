package io.getlime.security;

import io.getlime.security.soap.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;

/**
 * PowerAuth SOAP WebService Configuration
 *
 * @author Petr Dvorak
 */
@Configuration
@ComponentScan(basePackages = {"io.getlime.rest"})
public class PowerAuthWebServiceConfiguration {

    @Value("${powerauth.service.url}")
    private String powerAuthServiceUrl;

    /**
     * Return SOAP service marshaller.
     *
     * @return Marshaller instance with a correct context path.
     */
    @Bean
    public Jaxb2Marshaller marshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPath("io.getlime.powerauth.soap");
        return marshaller;
    }

    /**
     * Return a correctly configured PowerAuthServiceClient instance.
     *
     * @param marshaller SOAP service marshaller.
     * @return Correctly configured PowerAuthServiceClient instance.
     */
    @Bean
    public PowerAuthServiceClient powerAuthClient(Jaxb2Marshaller marshaller) {
        PowerAuthServiceClient client = new PowerAuthServiceClient();
        client.setDefaultUri(powerAuthServiceUrl);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        return client;
    }

}