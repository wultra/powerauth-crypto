package io.getlime.banking.model;

public class ActivationCreateResponse {
	
	private String activationId;
	private String activationNonce;
	private String ephemeralPublicKey;
	private String cServerPublicKey;
	private String cServerPublicKeySignature;
	
	public String getActivationId() {
		return activationId;
	}
	
	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}
	
	public String getActivationNonce() {
		return activationNonce;
	}
	
	public void setActivationNonce(String activationNonce) {
		this.activationNonce = activationNonce;
	}
	
	public String getEphemeralPublicKey() {
		return ephemeralPublicKey;
	}
	
	public void setEphemeralPublicKey(String ephemeralPublicKey) {
		this.ephemeralPublicKey = ephemeralPublicKey;
	}
	
	public String getcServerPublicKey() {
		return cServerPublicKey;
	}
	
	public void setcServerPublicKey(String cServerPublicKey) {
		this.cServerPublicKey = cServerPublicKey;
	}
	
	public String getcServerPublicKeySignature() {
		return cServerPublicKeySignature;
	}
	
	public void setcServerPublicKeySignature(String cServerPublicKeySignature) {
		this.cServerPublicKeySignature = cServerPublicKeySignature;
	}

}
