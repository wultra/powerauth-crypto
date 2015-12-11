package io.getlime.rest.api.model;

public class ActivationCreateRequest {
	
	private String activationIdShort;
	private String activationNonce;
	private String cDevicePublicKey;
	private String clientName;
	
	public String getActivationIdShort() {
		return activationIdShort;
	}
	
	public void setActivationIdShort(String activationIdShort) {
		this.activationIdShort = activationIdShort;
	}
	
	public String getActivationNonce() {
		return activationNonce;
	}
	
	public void setActivationNonce(String activationNonce) {
		this.activationNonce = activationNonce;
	}
	
	public String getcDevicePublicKey() {
		return cDevicePublicKey;
	}
	
	public void setcDevicePublicKey(String cDevicePublicKey) {
		this.cDevicePublicKey = cDevicePublicKey;
	}
	
	public String getClientName() {
		return clientName;
	}
	
	public void setClientName(String clientName) {
		this.clientName = clientName;
	}
	
}
