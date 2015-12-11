package io.getlime.rest.api.security.exception;

public class PowerAuthAuthenticationException extends Exception {

	private static final long serialVersionUID = 4280095091435126237L;
	
	public PowerAuthAuthenticationException() {
		super();
	}
	
	public PowerAuthAuthenticationException(String message) {
		super(message);
	}

}
