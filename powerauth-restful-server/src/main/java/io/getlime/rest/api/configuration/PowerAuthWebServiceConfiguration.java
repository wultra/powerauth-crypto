package io.getlime.rest.api.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;

import io.getlime.security.soap.client.PowerAuthServiceClient;

@Configuration
@ComponentScan(basePackages = {"io.getlime.rest"})
public class PowerAuthWebServiceConfiguration {
	
	@Value("${powerauth.service.url}")
	private String powerAuthServiceUrl;

	@Bean
	public Jaxb2Marshaller marshaller() {
		Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
		marshaller.setContextPath("io.getlime.powerauth.soap");
		return marshaller;
	}

	@Bean
	public PowerAuthServiceClient powerAuthClient(Jaxb2Marshaller marshaller) {
		PowerAuthServiceClient client = new PowerAuthServiceClient();
		client.setDefaultUri(powerAuthServiceUrl);
		client.setMarshaller(marshaller);
		client.setUnmarshaller(marshaller);
		return client;
	}

}
