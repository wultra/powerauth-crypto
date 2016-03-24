/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;

import io.getlime.security.soap.client.PowerAuthServiceClient;

/**
 * Default PowerAuth Service configuration.
 * 
 * @author Petr Dvorak
 *
 */
@Configuration
@ComponentScan(basePackages = {"io.getlime.rest"})
public class PowerAuthWebServiceConfiguration {
	
	@Value("${powerauth.service.url}")
	private String powerAuthServiceUrl;

	/**
	 * Marshaller for PowerAuth SOAP service communication.
	 * @return JAXB marshaller with correctly configured context path.
	 */
	@Bean
	public Jaxb2Marshaller marshaller() {
		Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
		marshaller.setContextPath("io.getlime.powerauth.soap");
		return marshaller;
	}

	/**
	 * Prepare a correctly configured PowerAuthServiceClient instance with the service
	 * URL specified using 'powerauth.service.url' server property.
	 * @param marshaller JAXB marshaller
	 * @return Correctly configured PowerAuthServiceClient instance with the service
	 * URL specified using 'powerauth.service.url' server property
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
