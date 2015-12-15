package io.getlime.rest.api.model;

public class PowerAuthAPIRequest<T> {
	
	private T requestObject;
	
	public PowerAuthAPIRequest() {
    }
	
	public PowerAuthAPIRequest(T requestObject) {
		this.requestObject = requestObject;
	}
	
	public T getRequestObject() {
		return requestObject;
	}
	
	public void setRequestObject(T requestObject) {
		this.requestObject = requestObject;
	}

}
