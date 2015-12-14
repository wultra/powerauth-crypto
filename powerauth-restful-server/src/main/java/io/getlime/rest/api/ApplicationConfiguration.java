package io.getlime.rest.api;

import org.springframework.context.annotation.Configuration;

import io.getlime.rest.api.security.application.PowerAuthApplicationConfiguration;

@Configuration
public class ApplicationConfiguration implements PowerAuthApplicationConfiguration {
	
	private static final String expectedApplicationId = "a1c97807-795a-466e-87bf-230d8ac1451e";
	private static final String expectedApplicationSecret = "d358e78a-8d12-4595-bf69-6eff2c2afc04";

	@Override
	public String getApplicationSecretForApplicationId(String applicationId) {
		if (applicationId.equals(ApplicationConfiguration.expectedApplicationId)) {
			return ApplicationConfiguration.expectedApplicationSecret;
		}
		return null;
	}

}
