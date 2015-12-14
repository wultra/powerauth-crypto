package io.getlime.rest.api.security.application;

public interface PowerAuthApplicationConfiguration {
	
	public String getApplicationSecretForApplicationId(String applicationId);

}
