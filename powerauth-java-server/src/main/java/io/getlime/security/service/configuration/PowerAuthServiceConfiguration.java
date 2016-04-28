package io.getlime.security.service.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Class holding the configuration data of this PowerAuth 2.0 Server
 * instance. Default values are in "application.properties" file.
 * 
 * @author Petr Dvorak
 *
 */
@Configuration
public class PowerAuthServiceConfiguration {

	@Value("${powerauth.service.applicationName}")
	private String applicationName;
	
	@Value("${powerauth.service.applicationDisplayName}")
	private String applicationDisplayName;
	
	@Value("${powerauth.service.applicationEnvironment}")
	private String applicationEnvironment;
	
	/**
	 * Get application name, usually used as a "unique code" for the application within
	 * a server infrastructure.
	 * @return Application name.
	 */
	public String getApplicationName() {
		return applicationName;
	}
	
	/**
	 * Set application name.
	 * @param applicationName Application name.
	 */
	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}
	
	/**
	 * Get application display name, usually used as a "visual representation" of the
	 * application within a server infrastructure.
	 * @return Application display name.
	 */
	public String getApplicationDisplayName() {
		return applicationDisplayName;
	}
	
	/**
	 * Set application display name.
	 * @param applicationDisplayName Application display name.
	 */
	public void setApplicationDisplayName(String applicationDisplayName) {
		this.applicationDisplayName = applicationDisplayName;
	}
	
	/**
	 * Get the application environment name.
	 * @return Application environment name.
	 */
	public String getApplicationEnvironment() {
		return applicationEnvironment;
	}
	
	/**
	 * Set the application environment name.
	 * @param applicationEnvironment Application environment name.
	 */
	public void setApplicationEnvironment(String applicationEnvironment) {
		this.applicationEnvironment = applicationEnvironment;
	}
	
}
