package io.getlime.banking.model;

public class ActivationStatusResponse {
	
	private String activationId;
	private String cStatusBlob;
	
	public String getActivationId() {
		return activationId;
	}
	
	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}
	
	public String getcStatusBlob() {
		return cStatusBlob;
	}
	
	public void setcStatusBlob(String cStatusBlob) {
		this.cStatusBlob = cStatusBlob;
	}

}
