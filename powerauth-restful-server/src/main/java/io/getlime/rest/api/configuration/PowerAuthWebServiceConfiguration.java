package io.getlime.rest.api.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;

import io.getlime.security.soap.client.PowerAuthServiceClient;

@Configuration
@ComponentScan(basePackages = {"io.getlime.rest"})
public class PowerAuthWebServiceConfiguration {
	
	@Bean
	public Jaxb2Marshaller marshaller() {
		Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
		marshaller.setContextPath("io.getlime.powerauth.soap");
		return marshaller;
	}

	@Bean
	public PowerAuthServiceClient powerAuthClient(Jaxb2Marshaller marshaller) {
		PowerAuthServiceClient client = new PowerAuthServiceClient();
		client.setDefaultUri("http://localhost:8080/powerauth-java-server/powerauth");
		client.setMarshaller(marshaller);
		client.setUnmarshaller(marshaller);
		return client;
	}

}
