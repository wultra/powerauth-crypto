package io.getlime.security;

import io.getlime.security.soap.client.PowerAuthServiceClient;
import org.apache.ws.security.WSConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.ws.client.support.interceptor.ClientInterceptor;
import org.springframework.ws.soap.security.wss4j.Wss4jSecurityInterceptor;

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

    @Value("${powerauth.service.security.clientToken}")
    private String clientToken;

    @Value("${powerauth.service.security.clientSecret}")
    private String clientSecret;

    /**
     * Checks if given client token is the current client token.
     * @param clientToken Client Token to be checked.
     * @return True if the provided client token is the same one as the one being used, false otherwise.
     */
    public boolean isCurrentSecuritySettings(String clientToken) {
        if (this.clientToken == null) {
            return false;
        }
        return this.clientToken.equals(clientToken);
    }

    /**
     * Return WS-Security interceptor instance using UsernameToken authentication.
     * @return Wss4jSecurityInterceptor instance.
     */
    @Bean
    public Wss4jSecurityInterceptor securityInterceptor(){
        Wss4jSecurityInterceptor wss4jSecurityInterceptor = new Wss4jSecurityInterceptor();
        wss4jSecurityInterceptor.setSecurementActions("UsernameToken");
        wss4jSecurityInterceptor.setSecurementUsername(clientToken);
        wss4jSecurityInterceptor.setSecurementPassword(clientSecret);
        wss4jSecurityInterceptor.setSecurementPasswordType(WSConstants.PW_TEXT);
        return wss4jSecurityInterceptor;
    }

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
        // if there is a configuration with security credentials, add interceptor
        if (!clientToken.isEmpty()) {
            ClientInterceptor[] interceptors = new ClientInterceptor[] {
                    securityInterceptor()
            };
            client.setInterceptors(interceptors);
        }
        return client;
    }

}