package io.getlime.rest.api.model;

public class PowerAuthAPIResponse<T> {

	private String status;
	private T responseObject;
	
	public PowerAuthAPIResponse(String status, T responseObject) {
		this.status = status;
		this.responseObject = responseObject;
	}
	
	public String getStatus() {
		return status;
	}
	
	public T getResponseObject() {
		return responseObject;
	}
	
	public void setStatus(String status) {
		this.status = status;
	}
	
	public void setResponseObject(T responseObject) {
		this.responseObject = responseObject;
	}
	
}
