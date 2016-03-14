package io.getlime.rest.api.model;

public class ErrorModel {
	
	private String code;
	private String message;

	public ErrorModel(String code, String message) {
			super();
			this.code = code;
			this.message = message;
		}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
	
	public String getCode() {
		return code;
	}
	
	public void setCode(String code) {
		this.code = code;
	}
	
	public String getLocalizedMessage() {
		return message;
	}

}